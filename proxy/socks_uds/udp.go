package socks_uds

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type udpDispatcher struct {
	sync.RWMutex
	links      map[net.Destination]*transport.Link
	conn       stdnet.Conn
	wMutex     sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	disp       routing.Dispatcher
	clientAddr stdnet.Addr
}

func newUDPDispatcher(ctx context.Context, clientAddr stdnet.Addr, conn stdnet.Conn, disp routing.Dispatcher) *udpDispatcher {
	c, cancel := context.WithCancel(ctx)
	return &udpDispatcher{
		links:      make(map[net.Destination]*transport.Link),
		conn:       conn,
		ctx:        c,
		cancel:     cancel,
		disp:       disp,
		clientAddr: clientAddr,
	}
}

func (d *udpDispatcher) Dispatch(dest net.Destination, payload *buf.Buffer) error {
	d.RLock()
	link, ok := d.links[dest]
	d.RUnlock()

	if !ok {
		d.Lock()
		link, ok = d.links[dest]
		if !ok {
			// 为独立的 UDP Destination 创建专属 Access Log 记录
			udpCtx := log.ContextWithAccessMessage(d.ctx, &log.AccessMessage{
				From:   d.clientAddr,
				To:     dest,
				Status: log.AccessAccepted,
				Reason: "",
			})
			newLink, err := d.disp.Dispatch(udpCtx, dest)
			if err != nil {
				d.Unlock()
				return err
			}
			link = newLink
			d.links[dest] = link
			go d.handleDownlink(dest, link.Reader) // 并发监听下行回包
		}
		d.Unlock()
	}

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{payload})
}

func (d *udpDispatcher) handleDownlink(dest net.Destination, reader buf.Reader) {
	defer func() {
		d.Lock()
		delete(d.links, dest)
		d.Unlock()
	}()

	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return // Dispatcher 已关闭目标地址通道
		}

		d.wMutex.Lock()
		for _, b := range mb {
			// SOCKS5 UDP 回包 Header 封装: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT
			headerLen := 4
			var atyp byte
			var addr []byte

			if dest.Address.Family().IsIPv4() {
				atyp = 0x01
				addr = dest.Address.IP()
				headerLen += 4
			} else if dest.Address.Family().IsIPv6() {
				atyp = 0x04
				addr = dest.Address.IP()
				headerLen += 16
			} else {
				atyp = 0x03
				domain := dest.Address.Domain()
				addr = append([]byte{byte(len(domain))}, []byte(domain)...)
				headerLen += 1 + len(domain)
			}
			headerLen += 2

			totalLen := uint16(headerLen + int(b.Len()))

			// 写入 2 字节长度头 (大端)
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, totalLen)
			d.writer.Write(lenBuf)

			// 写入 SOCKS5 UDP 头部
			d.writer.Write([]byte{0x00, 0x00, 0x00, atyp})
			d.writer.Write(addr)
			portBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(portBuf, uint16(dest.Port))
			d.writer.Write(portBuf)

			// 写入实际 UDP 载荷
			d.writer.Write(b.Bytes())
			b.Release() // 处理完毕立即返还内存池
		}
		d.writer.Flush()
		d.wMutex.Unlock()
	}
}

func handleUDPOverStream(ctx context.Context, clientAddr net.Addr, reader *buf.BufferedReader, writer *buf.BufferedWriter, dispatcher routing.Dispatcher) error {
	disp := newUDPDispatcher(ctx, clientAddr, writer, dispatcher)
	defer disp.cancel()

	for {
		// 1. 读取 2 字节头
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(reader, lenBuf); err != nil {
			return err
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)

		// 防止异常巨型包打爆 2KB 内建池
		if int32(pktLen) > buf.Size {
			return newError("UDP packet too large")
		}

		// 2. 读取封包 (直接用内置 Extend 获取切片边界)
		payload := buf.New()
		targetBuf := payload.Extend(int32(pktLen))
		if _, err := io.ReadFull(reader, targetBuf); err != nil {
			payload.Release()
			return err
		}

		// 3. 解析客户端 SOCKS5 UDP Header (RSV + FRAG + ATYP + ADDR + PORT)
		if payload.Len() < 4 {
			payload.Release()
			continue
		}
		data := payload.Bytes()
		atyp := data[3]
		offset := 4

		var dest net.Destination
		dest.Network = net.Network_UDP

		switch atyp {
		case 0x01: // IPv4
			if payload.Len() < int32(offset+6) {
				payload.Release()
				continue
			}
			dest.Address = net.IPAddress(data[offset : offset+4])
			dest.Port = net.PortFromBytes(data[offset+4 : offset+6])
			offset += 6
		case 0x03: // Domain
			if payload.Len() < int32(offset+1) {
				payload.Release()
				continue
			}
			domainLen := int(data[offset])
			offset++
			if payload.Len() < int32(offset+domainLen+2) {
				payload.Release()
				continue
			}
			dest.Address = net.DomainAddress(string(data[offset : offset+domainLen]))
			offset += domainLen
			dest.Port = net.PortFromBytes(data[offset+domainLen : offset+domainLen+2])
			offset += domainLen + 2
		case 0x04: // IPv6
			if payload.Len() < int32(offset+18) {
				payload.Release()
				continue
			}
			dest.Address = net.IPAddress(data[offset : offset+16])
			dest.Port = net.PortFromBytes(data[offset+16 : offset+18])
			offset += 18
		default:
			payload.Release()
			continue
		}

		// 裁去解析完的 SOCKS5 UDP Header，仅保留核心载荷移交 Xray 路由
		payload.Advance(int32(offset))

		// 4. 交给分发器打到对应的远端 UDP 地址
		if err := disp.Dispatch(dest, payload); err != nil {
			newError("failed to dispatch UDP payload").Base(err).WriteToLog(session.ExportIDToError(ctx))
			payload.Release()
		}
	}
}