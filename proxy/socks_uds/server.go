package socks_uds

import (
	"context"
	"io"
	stdnet "net"
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

func (s *Server) Process(ctx context.Context, network net.Network, connection stdnet.Conn, dispatcher routing.Dispatcher) error {
	defer connection.Close()

	// 极简 1 字节读取闭包，替代臃肿的 BufferedReader
	readByte := func() (byte, error) {
		var b [1]byte
		_, err := io.ReadFull(connection, b[:])
		return b[0], err
	}

	// 1. SOCKS5 握手认证
	b, err := readByte()
	if err != nil { return newError("failed to read version") }
	if b != 0x05 { return newError("unexpected version") }
	
	nMethods, err := readByte()
	if err != nil { return newError("failed to read methods count") }
	
	methods := make([]byte, int(nMethods))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return newError("failed to read methods")
	}

	// 2. 回复无认证 (0x05 0x00)
	if _, err := connection.Write([]byte{0x05, 0x00}); err != nil { return err }

	// 3. 读取请求
	b, err = readByte()
	if err != nil || b != 0x05 { return newError("failed to read request version") }
	cmd, err := readByte()
	if err != nil { return newError("failed to read request cmd") }
	_, err = readByte() // 跳过 RSV
	if err != nil { return newError("failed to skip RSV") }
	atyp, err := readByte()
	if err != nil { return newError("failed to read request atyp") }

	var dest net.Destination
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(connection, ip); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(connection, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.IPAddress(ip), net.PortFromBytes(portBuf))
	case 0x03: // Domain
		domainLen, err := readByte()
		if err != nil { return err }
		domain := make([]byte, int(domainLen))
		if _, err := io.ReadFull(connection, domain); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(connection, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.DomainAddress(string(domain)), net.PortFromBytes(portBuf))
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(connection, ip); err != nil { return err }
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(connection, portBuf); err != nil { return err }
		dest = net.TCPDestination(net.IPAddress(ip), net.PortFromBytes(portBuf))
	default:
		return newError("unknown ATYP")
	}

	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   connection.RemoteAddr(),
		To:     dest,
		Status: log.AccessAccepted,
		Reason: "",
	})

	// 4. 指令路由
	if cmd == 0x01 { // TCP CONNECT
		dest.Network = net.Network_TCP
		return s.handleTCP(ctx, dest, connection, dispatcher)
	}

	if cmd == 0x03 { // UDP ASSOCIATE
		dest.Network = net.Network_UDP

		localAddr := connection.LocalAddr().String()
		if !strings.Contains(localAddr, "/") && !strings.HasPrefix(localAddr, "@") {
			localAddr = "uds" // Fallback 保底
		}
		pathLen := len(localAddr)
		if pathLen > 255 {
			localAddr = localAddr[:255]
			pathLen = 255
		}

		// 构造私有握手响应: VER(5) REP(0) RSV(0) ATYP(5) ADDR_LEN(pathLen) ADDR PORT(0)
		resp := []byte{0x05, 0x00, 0x00, 0x05, byte(pathLen)}
		resp = append(resp, []byte(localAddr)...)
		resp = append(resp, 0x00, 0x00)

		if _, err := connection.Write(resp); err != nil { return err }

		// 不关闭连接，全移交给 UDP 流处理器
		return handleUDPOverStream(ctx, connection.RemoteAddr(), connection, dispatcher)
	}

	return newError("unsupported command")
}

func (s *Server) handleTCP(ctx context.Context, dest net.Destination, connection stdnet.Conn, dispatcher routing.Dispatcher) error {
	link, err := dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return err
	}
	
	// 立即回吐 TCP 成功包
	if _, err := connection.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	requestReader := buf.NewReader(connection)
	responseWriter := buf.NewWriter(connection)

	err = task.Run(ctx, func() error {
		defer common.Close(link.Writer)
		return buf.Copy(requestReader, link.Writer)
	}, func() error {
		return buf.Copy(link.Reader, responseWriter)
	})

	common.Interrupt(link.Reader)
	common.Interrupt(link.Writer)
	return err
}