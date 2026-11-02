package socks_uds

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
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
	closed     bool
	workers    sync.WaitGroup
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

func (d *udpDispatcher) Close() error {
	d.cancel()
	err := d.conn.Close()
	d.Lock()
	d.closed = true
	links := d.links
	d.links = nil
	d.Unlock()
	for _, link := range links {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
	}
	d.workers.Wait()
	return err
}

// Dispatch takes ownership of payload on success and failure, like buf.Writer.
func (d *udpDispatcher) Dispatch(dest net.Destination, payload buf.MultiBuffer) error {
	d.RLock()
	if d.closed {
		d.RUnlock()
		buf.ReleaseMulti(payload)
		return errors.New("UDP association is closed")
	}
	link, ok := d.links[dest]
	d.RUnlock()

	if !ok {
		d.Lock()
		if d.closed {
			d.Unlock()
			buf.ReleaseMulti(payload)
			return errors.New("UDP association is closed")
		}
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
				buf.ReleaseMulti(payload)
				return err
			}
			link = newLink
			d.links[dest] = link
			d.workers.Add(1)
			go d.handleDownlink(dest, link)
		}
		d.Unlock()
	}

	return link.Writer.WriteMultiBuffer(payload)
}

func (d *udpDispatcher) handleDownlink(dest net.Destination, link *transport.Link) {
	defer d.workers.Done()
	defer func() {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		d.Lock()
		if d.links[dest] == link {
			delete(d.links, dest)
		}
		d.Unlock()
	}()

	// Reuse the destination header for each packet on this link.
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

	// The association serializes complete frames, including their length prefix.
	hdrBuf := make([]byte, 2+len(baseHeader))
	copy(hdrBuf[2:], baseHeader)

	for {
		mb, err := link.Reader.ReadMultiBuffer()

		d.wMutex.Lock()
		for i, b := range mb {
			if int(b.Len()) > 65535-len(baseHeader) {
				b.Release()
				continue
			}
			totalLen := uint16(len(baseHeader) + int(b.Len()))
			binary.BigEndian.PutUint16(hdrBuf[:2], totalLen)

			// Keep payload storage separate; eligible sockets can use writev.
			buffers := stdnet.Buffers{hdrBuf, b.Bytes()}
			if _, err := buffers.WriteTo(d.conn); err != nil {
				for j := i; j < len(mb); j++ {
					mb[j].Release()
				}
				d.wMutex.Unlock()
				d.cancel()
				_ = d.conn.Close()
				return
			}
			b.Release()
		}
		d.wMutex.Unlock()
		if err != nil {
			return
		}
	}
}

func handleUDPOverStream(ctx context.Context, clientAddr stdnet.Addr, conn stdnet.Conn, dispatcher routing.Dispatcher) error {
	disp := newUDPDispatcher(ctx, clientAddr, conn, dispatcher)
	defer disp.Close()

	lenBuf := make([]byte, 2)
	for {
		// 1. 读取 2 字节头
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		pktLen := binary.BigEndian.Uint16(lenBuf)

		// Preserve this protocol's fixed-size input contract and frame boundary.
		if int32(pktLen) > buf.Size {
			// Discard the entire oversized frame so the next packet stays aligned.
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
		_ = disp.Dispatch(dest, buf.MultiBuffer{payload})
	}
}
