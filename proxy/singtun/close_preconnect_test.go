//go:build with_sing_tun

package singtun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// This exercises the real VLESS preconnection receive, not a simulated
// dispatcher that merely ignores cancellation. The dialer is released only
// during cleanup, so the native flow can finish only when VLESS.Close closes
// preConns. Both feature orders are supported by core.Config's protobuf API;
// the JSON builder currently registers the outbound manager first.
func TestNativeCoreCloseWhileVLESSPreconnectPending(t *testing.T) {
	for _, inboundFirst := range []bool{false, true} {
		name := "outbound_before_inbound"
		if inboundFirst {
			name = "inbound_before_outbound"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newClosePreconnectFixture(t, inboundFirst, false)
			closed := make(chan error, 1)
			go func() { closed <- fixture.instance.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				// Rescue before reporting the regression: otherwise the test and
				// its cleanup would be stuck in exactly the deadlock under review.
				select {
				case <-fixture.in.entered:
				default:
					t.Error("Core.Close has not entered native inbound cleanup")
				}
				select {
				case <-fixture.dispatch.ctx.Done():
				default:
					t.Error("native cleanup did not cancel the flow context")
				}
				select {
				case <-fixture.out.closed:
					t.Error("outbound was already closed while native cleanup remained blocked")
				default:
				}
				_ = fixture.out.Close()
				select {
				case err := <-closed:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(time.Second):
					t.Fatal("explicit VLESS.Close did not release Core.Close")
				}
				t.Fatal("Core.Close waited on a cancelled native dispatch until the later VLESS outbound was explicitly closed")
			}
			select {
			case <-fixture.out.returned:
			case <-time.After(time.Second):
				t.Fatal("VLESS dispatch did not finish after Core.Close")
			}
		})
	}
}

func TestNativeCloseReleasesIOBeforeForeignDispatchReturns(t *testing.T) {
	for _, udp := range []bool{false, true} {
		name := "tcp"
		if udp {
			name = "udp"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newClosePreconnectFixture(t, true, udp)
			closed := make(chan error, 8)
			for range cap(closed) {
				go func() { closed <- fixture.native.Close() }()
			}
			for range cap(closed) {
				select {
				case err := <-closed:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					_ = fixture.out.Close()
					t.Fatal("Native.Close waited for the foreign VLESS dispatch")
				}
			}
			select {
			case <-fixture.dispatch.ctx.Done():
			default:
				t.Fatal("Native.Close did not cancel the flow")
			}
			select {
			case <-fixture.out.closed:
				t.Fatal("Native.Close closed the foreign outbound")
			case <-fixture.out.returned:
				t.Fatal("gated VLESS dispatch unexpectedly returned before outbound.Close")
			default:
			}
			if _, err := fixture.run.device.Write([]byte{0}); err == nil {
				t.Fatal("native device remained open after Close")
			}
			if err := fixture.native.Start(); err == nil {
				t.Fatal("closed native handler restarted")
			}
			// The foreign processor has not unwound yet. Its retained link must
			// reject late IO instead of touching a closed/reused native descriptor.
			packet := buf.New()
			_, _ = packet.Write([]byte("late reply"))
			if err := fixture.dispatch.link.Writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err == nil {
				t.Fatal("retained native writer accepted data after Close")
			}
			read := make(chan error, 1)
			go func() {
				mb, err := fixture.dispatch.link.Reader.ReadMultiBuffer()
				buf.ReleaseMulti(mb)
				read <- err
			}()
			select {
			case err := <-read:
				if err == nil {
					t.Fatal("retained native reader remained open after Close")
				}
			case <-time.After(time.Second):
				t.Fatal("retained native reader blocked after Close")
			}
			_ = fixture.out.Close()
			select {
			case <-fixture.out.returned:
			case <-time.After(time.Second):
				t.Fatal("VLESS dispatch did not return after its owner closed it")
			}
		})
	}
}

type closePreconnectFixture struct {
	instance *core.Instance
	native   *Handler
	run      *stackSession
	out      *closePreconnectOutbound
	in       *closePreconnectInbound
	dispatch closePreconnectDispatch
}

func newClosePreconnectFixture(t *testing.T, inboundFirst, udp bool) *closePreconnectFixture {
	t.Helper()
	config := memoryCoreConfig(nil)
	config.Outbound = nil
	if !inboundFirst {
		config.App[1], config.App[2] = config.App[2], config.App[1]
	}
	instance, native := memoryCore(t, config, session.SniffingRequest{})
	processor, err := core.CreateObject(instance, &vlessout.Config{Vnext: &protocol.ServerEndpoint{
		Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: 443,
		User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
			Id: visionTestUUID, Encryption: "none", Testpre: 1,
		})},
	}})
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	dialer := &closePreconnectDialer{entered: make(chan struct{}), release: make(chan struct{}), conn: local}
	out := &closePreconnectOutbound{
		processor: processor.(*vlessout.Handler), dialer: dialer,
		entered: make(chan closePreconnectDispatch, 1), returned: make(chan error, 1), closed: make(chan struct{}),
	}
	om := instance.GetFeature(outbound.ManagerType()).(outbound.Manager)
	if err := om.AddHandler(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	peer := memoryPeer(t, native)
	in := &closePreconnectInbound{Handler: native, entered: make(chan struct{})}
	im := instance.GetFeature(inbound.ManagerType()).(inbound.Manager)
	if err := im.AddHandler(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	// Rescue must precede memoryPeer's handler.Close cleanup on a regression.
	t.Cleanup(func() {
		_ = out.Close()
		close(dialer.release)
		_ = local.Close()
		_ = remote.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	target := netip.MustParseAddrPort("192.0.2.10:443")
	if udp {
		conn, err := peer.DialUDP(netip.MustParseAddrPort("10.10.14.1:33001"), target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if _, err := conn.Write([]byte("first packet")); err != nil {
			t.Fatal(err)
		}
	} else {
		conn, err := peer.DialTCP(ctx, netip.MustParseAddr("10.10.14.1"), target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
	}
	fixture := &closePreconnectFixture{instance: instance, native: native, run: native.run, out: out, in: in}
	select {
	case fixture.dispatch = <-out.entered:
	case <-ctx.Done():
		t.Fatal("native flow did not reach VLESS")
	}
	select {
	case <-dialer.entered:
	case <-ctx.Done():
		t.Fatal("VLESS did not start its gated preconnection")
	}
	return fixture
}

type closePreconnectDialer struct {
	entered chan struct{}
	release chan struct{}
	conn    net.Conn
}

func (d *closePreconnectDialer) Dial(context.Context, xnet.Destination) (stat.Connection, error) {
	close(d.entered)
	<-d.release
	return d.conn, nil
}
func (*closePreconnectDialer) DestIpAddress() xnet.IP                                { return nil }
func (*closePreconnectDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

type closePreconnectOutbound struct {
	processor *vlessout.Handler
	dialer    *closePreconnectDialer
	entered   chan closePreconnectDispatch
	returned  chan error
	closed    chan struct{}
	once      sync.Once
}

type closePreconnectDispatch struct {
	ctx  context.Context
	link *transport.Link
}

func (*closePreconnectOutbound) Tag() string                          { return "gated-vless" }
func (*closePreconnectOutbound) Start() error                         { return nil }
func (*closePreconnectOutbound) SenderSettings() *serial.TypedMessage { return nil }
func (*closePreconnectOutbound) ProxySettings() *serial.TypedMessage  { return nil }
func (h *closePreconnectOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	h.entered <- closePreconnectDispatch{ctx: ctx, link: link}
	h.returned <- h.processor.Process(ctx, link, h.dialer)
}
func (h *closePreconnectOutbound) Close() error {
	h.once.Do(func() { close(h.closed); _ = h.processor.Close() })
	return nil
}

type closePreconnectInbound struct {
	*Handler
	entered chan struct{}
	once    sync.Once
}

func (*closePreconnectInbound) Tag() string                            { return integrationTag }
func (*closePreconnectInbound) Start() error                           { return nil }
func (*closePreconnectInbound) ReceiverSettings() *serial.TypedMessage { return nil }
func (*closePreconnectInbound) ProxySettings() *serial.TypedMessage    { return nil }
func (h *closePreconnectInbound) Close() error {
	h.once.Do(func() { close(h.entered) })
	return h.Handler.Close()
}
