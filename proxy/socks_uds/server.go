package socks_uds

import (
	"context"
	"io"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet"
)

// newError 生成该协议专属的层级错误信息
func newError(values ...interface{}) *errors.Error {
	return errors.New(values...).Path("Proxy", "SocksUDS")
}

type Server struct {
	config *ServerConfig
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	return &Server{config: config}, nil
}

func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func (s *Server) Process(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {
	reader := buf.NewBufferedReader(connection)
	writer := buf.NewBufferedWriter(connection)
	defer connection.Close()

	// 1. SOCKS5 握手认证
	b, err := reader.ReadByte()
	if err != nil {
		return newError("failed to read version").Base(err)
	}
	if b != 0x05 {
		return newError("unexpected version: ", b)
	}
	nMethods, err := reader.ReadByte()
	if err != nil {
		return newError("failed to read methods count").Base(err)
	}
	_, err = reader.ReadBytes(int32(nMethods))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return newError("failed to read methods").Base(err)
	}

	// 2. 回复无认证 (0x05 0x00)
	if err := writer.WriteByte(0x05); err != nil { return err }
	if err := writer.WriteByte(0x00); err != nil { return err }
	if err := writer.Flush(); err != nil { return err }

	// 3. 读取请求
	b, err = reader.ReadByte()
	if err != nil || b != 0x05 { return newError("failed to read request version") }
	cmd, err := reader.ReadByte()
	if err != nil { return newError("failed to read request cmd") }
	_, err = reader.ReadByte() // 跳过 RSV
	if err != nil { return newError("failed to skip RSV") }
	atyp, err := reader.ReadByte()
	if err != nil { return newError("failed to read request atyp") }

	var dest net.Destination
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(reader, ip); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.IPAddress(ip), net.PortFromBytes(portBuf))
	case 0x03: // Domain
		domainLen, err := reader.ReadByte()
		if err != nil { return err }
		domain := make([]byte, int(domainLen))
		if _, err := io.ReadFull(reader, domain); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.DomainAddress(string(domain)), net.PortFromBytes(portBuf))
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(reader, ip); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(reader, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.IPAddress(ip), net.PortFromBytes(portBuf))
	default:
		return newError("unknown ATYP")
	}

	// 为后续路由、流量统计和 Access Log 建立上下文
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   connection.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	// 4. 指令路由
	if cmd == 0x01 { // TCP CONNECT
		dest.Network = net.Network_TCP
		// 打印带有 Session ID 的生产级日志
		newError("TCP Connect request to ", dest).WriteToLog(session.ExportIDToError(ctx))
		return s.handleTCP(ctx, dest, reader, writer, dispatcher)
	}

	if cmd == 0x03 { // UDP ASSOCIATE
		dest.Network = net.Network_UDP
		newError("UDP Associate request over UDS initiated").WriteToLog(session.ExportIDToError(ctx))

		localAddr := connection.LocalAddr().String()
		if !strings.Contains(localAddr, "/") && !strings.HasPrefix(localAddr, "@") {
			localAddr = "uds" // Fallback 保底
		}
		pathLen := len(localAddr)
		if pathLen > 255 {
			localAddr = localAddr[:255]
			pathLen = 255
		}

		// 构造握手响应: VER(5) REP(0) RSV(0) ATYP(5) ADDR_LEN(pathLen) ADDR PORT(0)
		if err := writer.WriteByte(0x05); err != nil { return err }
		if err := writer.WriteByte(0x00); err != nil { return err }
		if err := writer.WriteByte(0x00); err != nil { return err }
		if err := writer.WriteByte(0x05); err != nil { return err } // 私有 ATYP 0x05
		if err := writer.WriteByte(byte(pathLen)); err != nil { return err }
		if _, err := writer.Write([]byte(localAddr)); err != nil { return err }
		if err := writer.WriteByte(0x00); err != nil { return err }
		if err := writer.WriteByte(0x00); err != nil { return err }
		if err := writer.Flush(); err != nil { return err }

		// 不关闭连接，切换为纯数据流通道处理 UDP
		return handleUDPOverStream(ctx, connection.RemoteAddr(), reader, writer, dispatcher)
	}

	return newError("unsupported command: ", cmd)
}

func (s *Server) handleTCP(ctx context.Context, dest net.Destination, reader *buf.BufferedReader, writer *buf.BufferedWriter, dispatcher routing.Dispatcher) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	// 成功响应 TCP
	writer.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	writer.Flush()

	// Dispatcher 会在这里处理基于上下文的嗅探逻辑 (若配置中 sniff 开启)
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}
	err = task.Run(ctx, func() error {
		defer common.Close(link.Writer)
		return buf.Copy(reader, link.Writer)
	}, func() error {
		return buf.Copy(link.Reader, writer)
	})

	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	return err
}