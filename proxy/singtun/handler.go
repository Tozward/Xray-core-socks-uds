//go:build with_sing_tun

package singtun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const Enabled = true

// Handler owns the optional stack and device. The existing TUN connection
// handler owns Xray session metadata, policy, statistics and dispatch semantics.
type Handler struct {
	ctx    context.Context
	config *Config
	native *tun.Handler
	mu     sync.Mutex
	run    *stackSession
	closed bool
}

type stackSession struct {
	stack  *stun.Go
	device stun.Tun
	flows  *flowHandler
	cancel context.CancelFunc
}

func NewHandler(ctx context.Context, config *Config) (*Handler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	object, err := common.CreateObject(ctx, &tun.Config{UserLevel: config.UserLevel})
	if err != nil {
		return nil, err
	}
	return &Handler{
		ctx: core.ToBackgroundDetachedContext(ctx), config: config,
		native: object.(*tun.Handler),
	}, nil
}

func (h *Handler) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return errors.New("sing-tun: inbound is closed")
	}
	if h.run != nil {
		return nil
	}
	options := h.options()
	device, err := openDevice(&options)
	if err != nil {
		return errors.New("sing-tun: open device").Base(err)
	}
	run, err := h.startDevice(device, options)
	if err != nil {
		return err
	}
	h.run = run
	return nil
}

func (h *Handler) options() stun.Options {
	options := stun.Options{
		Name: h.config.Name, MTU: h.config.Mtu,
		GSO: h.config.Gso, MultiQueue: h.config.MultiQueue,
		DNSMode: stun.DNSModeDisabled,
		// The host owns addresses, routes and DNS, including externally supplied
		// Android/iOS descriptors. Reevaluate against each pinned sing-tun update.
		EXP_ExternalConfiguration: true,
		Logger:                    stackLogger{Logger: logger.NOP(), ctx: h.ctx},
	}
	for _, address := range h.config.Address {
		prefix, _ := netip.ParsePrefix(address) // Validated before native allocation.
		if prefix.Addr().Is4() {
			options.Inet4Address = append(options.Inet4Address, prefix)
		} else {
			options.Inet6Address = append(options.Inet6Address, prefix)
		}
	}
	return options
}

// startDevice takes device ownership on both success and failure. MemoryTun
// uses this same path in tests; it introduces no production forwarding shim.
func (h *Handler) startDevice(device stun.Tun, options stun.Options) (*stackSession, error) {
	ctx, cancel := context.WithCancel(h.ctx)
	flows := &flowHandler{native: h.native, mtu: int(h.config.Mtu)}
	stack, err := stun.NewGo(stun.StackOptions{
		Context: ctx, Tun: device, TunOptions: options, Handler: flows,
		Logger: options.Logger, UDPTimeout: time.Minute, ICMPTimeout: 10 * time.Second,
		// A destination receives its own routing/sniffing decision. A second UDP
		// destination must not inherit the first destination's selected outbound.
		UDPMapping:    stun.NATMappingAddressAndPortDependent,
		TCPLocalJumbo: h.config.TcpLocalJumbo,
	})
	if err == nil {
		err = device.Start()
	}
	if err == nil {
		err = stack.Start()
	}
	if err != nil {
		flows.stop()
		cancel()
		if stack != nil {
			_ = stack.Close()
		}
		flows.wg.Wait()
		_ = device.Close()
		return nil, errors.New("sing-tun: start stack").Base(err)
	}
	return &stackSession{stack: stack, device: device, flows: flows, cancel: cancel}, nil
}

func (h *Handler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	run := h.run
	h.run = nil
	if run == nil {
		return nil
	}
	run.flows.stop()
	run.cancel()
	err := run.stack.Close()
	run.flows.wg.Wait()
	return errors.Combine(err, run.device.Close())
}

func (*Handler) Network() []xnet.Network { return nil }

func (*Handler) Process(context.Context, xnet.Network, stat.Connection, routing.Dispatcher) error {
	return errors.New("sing-tun does not accept socket connections")
}

type flowHandler struct {
	native *tun.Handler
	mtu    int
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (h *flowHandler) begin() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.wg.Add(1)
	return true
}

func (h *flowHandler) stop() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
}

func (*flowHandler) JudgeFlow(protocol uint8, _, destination netip.AddrPort, _ []byte) stun.FlowVerdict {
	if (protocol == 6 || protocol == 17) && destination.Port() != 0 {
		return stun.FlowVerdict{Action: stun.ActionAccept}
	}
	// Xray proxy outbounds carry TCP/UDP; never send ICMP through a direct
	// native bypass. Local/remote ICMP reachability is not supplied by this inbound.
	return stun.FlowVerdict{Action: stun.ActionReject}
}

func (*flowHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {
	// No DNS hijack verdict is emitted. Xray routing owns DNS interception.
}

func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !h.begin() {
		rejectConnection(conn, onClose)
		return
	}
	defer h.wg.Done()
	// Match Xray TUN's accepted connection semantics. In particular, sniffing
	// must be able to read the client's data after its TCP handshake completes.
	err := N.ReportHandshakeSuccess(conn)
	if err == nil {
		stream := conn
		if native, ok := conn.(*stun.GoConn); ok {
			stream = &tcpConn{
				GoConn:      native,
				source:      toDestination(source, xnet.Network_TCP).RawNetAddr(),
				destination: toDestination(destination, xnet.Network_TCP).RawNetAddr(),
			}
		}
		h.native.HandleConnectionContext(ctx, stream, toDestination(destination, xnet.Network_TCP))
	} else {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(err)
	}
}

func (h *flowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !h.begin() {
		rejectConnection(conn, onClose)
		return
	}
	defer h.wg.Done()
	packetConn, err := newPacketConn(conn, source, destination, h.mtu)
	if err == nil {
		h.native.HandleConnectionContext(ctx, packetConn, packetConn.destination)
	} else {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(err)
	}
}

func rejectConnection(conn io.Closer, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(net.ErrClosed)
	}
}

func toDestination(address M.Socksaddr, network xnet.Network) xnet.Destination {
	return xnet.Destination{Network: network, Address: xnet.IPAddress(address.Addr.AsSlice()), Port: xnet.Port(address.Port)}
}

type stackLogger struct {
	logger.Logger
	ctx context.Context
}

func (l stackLogger) Warn(args ...any) {
	errors.LogWarning(l.ctx, append([]any{"sing-tun: "}, args...)...)
}

func (l stackLogger) Error(args ...any) {
	errors.LogError(l.ctx, append([]any{"sing-tun: "}, args...)...)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewHandler(ctx, config.(*Config))
	}))
}
