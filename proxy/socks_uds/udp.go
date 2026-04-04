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

func (d *udpDispatcher) Dispatch(dest net.Destination, payload buf.MultiBuffer) error {
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

	return link.Writer.WriteMultiBuffer(payload)
}

func (d *udpDispatcher) handleDownlink(dest net.Destination, reader buf.Reader) {
	defer func() {
		d.Lock()
		delete(d.links, dest)
		d.Unlock()
	}()

	// 优化 1：针对固定的目标地址，在循环外预先计算基础 Header，完全消除循环内因为拼接带来的内存分配
	var atyp byte
	var addr []byte
	if dest.Address.Family().IsIPv4() {
		atyp = 0x01
		addr = dest.Address.IP()
	} else if dest.Address.Family().IsIPv6() {
		atyp = 0x04
		addr = dest.Address.IP()
	} else {
		atyp = 0x03
		domain := dest.Address.Domain()
		addr = append([]byte{byte(len(domain))}, []byte(domain)...)
	}

	baseHeader := []byte{0x00, 0x00, 0x00, atyp}
	baseHeader = append(baseHeader, addr...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(dest.Port))
	baseHeader = append(baseHeader, portBuf...)

	// 预分配带有长度位（前 2 字节）的头缓冲区，供循环内极速复用
	hdrBuf := make([]byte, 2+len(baseHeader))
	copy(hdrBuf[2:], baseHeader)

	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			return 
		}

		d.wMutex.Lock()
		for i, b := range mb {
			totalLen := uint16(len(baseHeader) + int(b.Len()))
			binary.BigEndian.PutUint16(hdrBuf[:2], totalLen)

			// 优化 2：利用 net.Buffers 触发底层 writev 机制（0 次 Payload 拷贝，1 次 Syscall）
			buffers := stdnet.Buffers{hdrBuf, b.Bytes()}
			if _, err := buffers.WriteTo(d.conn); err != nil {
				// 优化 3：检测到写入失败，释放剩余内存并立刻退出，防止 Goroutine 空转泄露
				for j := i; j < len(mb); j++ {
					mb[j].Release()
				}
				d.wMutex.Unlock()
				return
			}
			b.Release() 
		}
		d.wMutex.Unlock()
	}
}

func handleUDPOverStream(ctx context.Context, clientAddr stdnet.Addr, conn stdnet.Conn, dispatcher routing.Dispatcher) error {
	disp := newUDPDispatcher(ctx, clientAddr, conn, dispatcher)
	defer disp.cancel()

	lenBuf := make([]byte, 2)
	for {
		// 1. 读取 2 字节头
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)

		// Xray 的 UDP 架构硬性限制：单包必须存放在单个 buf.Buffer 内（容量 2KB）。
		// 遇到超大包不能 return error，否则会切断整条 UDS 流导致断网
		if int32(pktLen) > buf.Size {
			// 安全策略：将超大包从流中完整读取并静默丢弃，保持 UDS 字节流边界同步。
			// (大型 UDP 应当由客户端的 Tun 接口设置 MTU=1500 在 IP 层自动切片解决)
			if _, err := io.CopyN(io.Discard, conn, int64(pktLen)); err != nil {
				return err
			}
			continue
		}

		// 2. 读取封包
		payload := buf.New()
		targetBuf := payload.Extend(int32(pktLen))
		if _, err := io.ReadFull(conn, targetBuf); err != nil {
			payload.Release()
			return err
		}

		// 3. 解析客户端 SOCKS5 UDP Header
		if payload.Len() < 4 {
			payload.Release()
			continue
		}
		data := payload.Bytes()

		// 标准 SOCKS5 协议规范：如果 FRAG (分片号) 不为 0，且系统不支持组装，必须丢弃
		if data[2] != 0x00 {
			payload.Release()
			continue
		}

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
			dest.Port = net.PortFromBytes(data[offset : offset+2])
			offset += 2
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

		// 裁去解析完的 SOCKS5 UDP Header
		payload.Advance(int32(offset))

		// 4. 交给分发器打到对应的远端 UDP 地址
		if err := disp.Dispatch(dest, buf.MultiBuffer{payload}); err != nil {
			payload.Release()
		}
	}
}