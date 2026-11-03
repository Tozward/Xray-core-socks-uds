//go:build with_sing_tun

package singtun

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"os"
	"sync"

	sbuf "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// packetConn adapts packet ownership and addressing, without a socket or pipe.
// Xray may retain a Reader's buffers, so borrowed native receive buffers must
// be copied once before being released to sing-tun's independent allocator.
type packetConn struct {
	N.PacketConn
	waiter      N.PacketReadWaiter
	batch       N.PacketBatchWriter
	source      xnet.Destination
	destination xnet.Destination
	headroom    int
	maxBorrowed int
	writeMu     sync.Mutex
	// The existing write lock orders the initial reply against outbound failure.
	// An upstream reply must never race a rejection of its original request.
	handshakeDone bool
	outboundError error
	errorContext  context.Context
	// Most Xray packet writers submit one datagram at a time. Reuse only this
	// small slice backing storage; larger batches allocate bounded scratch.
	writePacket      [1]*sbuf.Buffer
	writeDestination [1]M.Socksaddr
}

func newPacketConn(conn N.PacketConn, source, destination M.Socksaddr, mtu int) (*packetConn, error) {
	waiter, ok := conn.(N.PacketReadWaiter)
	if !ok {
		return nil, errors.New("sing-tun: packet read waiter is unavailable")
	}
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	batch, _ := bufio.CreatePacketBatchWriter(conn)
	ipHeader := 40
	if source.IsIPv4() {
		ipHeader = 20
	}
	return &packetConn{
		PacketConn: conn, waiter: waiter, batch: batch,
		source:      toDestination(source, xnet.Network_UDP),
		destination: toDestination(destination, xnet.Network_UDP),
		headroom:    N.CalculateFrontHeadroom(conn), maxBorrowed: mtu - ipHeader - 8,
	}, nil
}

func (c *packetConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		packet, destination, err := c.waiter.WaitReadPacket()
		if err != nil {
			return nil, err
		}
		if packet.IsEmpty() {
			// Existing Xray copy paths do not carry zero-length UDP datagrams.
			packet.Release()
			continue
		}
		var payload *buf.Buffer
		if packet.Len() <= buf.Size {
			payload = buf.New()
		} else {
			payload = buf.NewWithSize(int32(packet.Len()))
		}
		_, _ = payload.Write(packet.Bytes())
		packet.Release()
		// EndpointOverrideReader may rewrite this value. Never let it alias the
		// connection's original destination or another packet's metadata.
		target := toDestination(destination, xnet.Network_UDP)
		payload.UDP = &target
		return buf.MultiBuffer{payload}, nil
	}
}

func (c *packetConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	defer buf.ReleaseMulti(mb)
	if c.outboundError != nil {
		return c.outboundError
	}
	if !c.handshakeDone && !mb.IsEmpty() {
		// Receiving upstream data establishes the outbound, before local delivery.
		// Match Sing's handshake contract and retain the original batch writes.
		c.handshakeDone = true
		if err := N.ReportHandshakeSuccess(c.PacketConn); err != nil {
			c.outboundError = err
			return err
		}
	}
	for len(mb) > 0 {
		count := min(len(mb), 16)
		var err error
		if count == 1 {
			err = c.writePackets(mb[:1], c.writePacket[:], c.writeDestination[:])
		} else {
			var packets [16]*sbuf.Buffer
			var destinations [16]M.Socksaddr
			err = c.writePackets(mb[:count], packets[:count], destinations[:count])
		}
		if err != nil {
			return err
		}
		mb = mb[count:]
	}
	return nil
}

// SubmitError receives Xray's existing outbound error feedback. Only an initial
// failure reports Sing's retained request snapshot; ordinary shutdown and errors
// after a successful reply must not generate an ICMP rejection.
func (c *packetConn) SubmitError(err error) {
	if err == nil {
		return
	}
	c.writeMu.Lock()
	if c.outboundError == nil {
		c.outboundError = err
	}
	if !c.handshakeDone {
		c.handshakeDone = true
		closed := goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) ||
			goerrors.Is(err, net.ErrClosed) || goerrors.Is(err, os.ErrClosed) ||
			goerrors.Is(err, context.Canceled)
		if !closed && (c.errorContext == nil || c.errorContext.Err() == nil) {
			// ICMP delivery is secondary; retain the authoritative outbound error.
			_ = N.ReportHandshakeFailure(c.PacketConn, err)
		}
	}
	c.writeMu.Unlock()
	// Preserve an originator's existing tracker, outside our IO lock: it may
	// cancel the flow or perform its own cleanup in response to this callback.
	if c.errorContext != nil {
		session.SubmitOutboundErrorToOriginator(c.errorContext, err)
	}
}

func (c *packetConn) dispatchError() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.outboundError
}

func (c *packetConn) writePackets(mb buf.MultiBuffer, packets []*sbuf.Buffer, destinations []M.Socksaddr) error {
	defer func() {
		// Native writers synchronously consume the buffers, including on error.
		// Never keep a borrowed payload or reply address in reusable scratch.
		clear(packets)
		clear(destinations)
	}()
	for index, payload := range mb {
		destination := c.destination
		if payload.UDP != nil && payload.UDP.Address != nil && payload.UDP.Address.Family().IsIP() {
			destination = *payload.UDP
		}
		destinations[index] = M.SocksaddrFrom(M.AddrFromIP(destination.Address.IP()).Unmap(), uint16(destination.Port))
		if c.batch != nil && int(payload.Len()) <= c.maxBorrowed {
			// Native batch writes synchronously consume payload views and build
			// their headers separately. No Xray buffer escapes this call.
			packets[index] = sbuf.As(payload.Bytes())
		} else {
			// Both fallback and fragmented writes prepend native headers. A
			// borrowed view has no headroom and would panic on this path.
			packet := sbuf.NewSize(c.headroom + int(payload.Len()))
			packet.Resize(c.headroom, 0)
			_, _ = packet.Write(payload.Bytes())
			packets[index] = packet
		}
	}
	if c.batch != nil {
		return c.batch.WritePacketBatch(packets, destinations)
	}
	for index, packet := range packets {
		if err := c.PacketConn.WritePacket(packet, destinations[index]); err != nil {
			sbuf.ReleaseMulti(packets[index+1:])
			return err
		}
	}
	return nil
}

// Native Handler uses only the MultiBuffer methods. The net.Conn shape supplies
// the same addresses and close/deadline contract as the existing TUN backend.
func (c *packetConn) LocalAddr() net.Addr  { return c.destination.RawNetAddr() }
func (c *packetConn) RemoteAddr() net.Addr { return c.source.RawNetAddr() }
func (c *packetConn) Read([]byte) (int, error) {
	return 0, errors.New("sing-tun UDP requires packet reads")
}

func (c *packetConn) Write([]byte) (int, error) {
	return 0, errors.New("sing-tun UDP requires packet writes")
}

var (
	_ net.Conn   = (*packetConn)(nil)
	_ buf.Reader = (*packetConn)(nil)
	_ buf.Writer = (*packetConn)(nil)
)
