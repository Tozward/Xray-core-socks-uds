//go:build with_sing_tun

package singtun

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	stun "github.com/sagernet/sing-tun"
	scommon "github.com/sagernet/sing/common"
	sbuf "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/net/dns/dnsmessage"
)

func TestPacketHandshakeReplyAndFailureAreOrdered(t *testing.T) {
	want := errors.New("outbound failed")
	t.Run("failure_before_reply", func(t *testing.T) {
		conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}
		adapter := newPacketTestAdapter(t, conn, false)
		adapter.SubmitError(want)
		adapter.SubmitError(want)
		packet := xrayPacket(t, []byte("too late"))
		if err := adapter.WriteMultiBuffer(buf.MultiBuffer{packet}); !errors.Is(err, want) {
			t.Fatalf("write after rejection: %v", err)
		}
		if packet.Cap() != 0 || conn.failures.Load() != 1 || conn.successes.Load() != 0 {
			t.Fatal("rejection did not consume the reply or reported handshake more than once")
		}
	})
	t.Run("reply_commits_before_waiting_failure", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		base := &nativePacketTestConn{onWrite: func(*sbuf.Buffer, M.Socksaddr) error {
			close(entered)
			<-release
			return nil
		}}
		conn := &udpFeedbackCountConn{nativePacketTestConn: base}
		adapter := newPacketTestAdapter(t, conn, false)
		written := make(chan error, 1)
		packet := xrayPacket(t, []byte("reply"))
		go func() { written <- adapter.WriteMultiBuffer(buf.MultiBuffer{packet}) }()
		<-entered
		submitting, submitted := make(chan struct{}), make(chan struct{})
		go func() { close(submitting); adapter.SubmitError(want); close(submitted) }()
		<-submitting
		close(release)
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		select {
		case <-submitted:
		case <-time.After(time.Second):
			t.Fatal("outbound feedback blocked after the packet write finished")
		}
		if conn.successes.Load() != 1 || conn.failures.Load() != 0 || !errors.Is(adapter.dispatchError(), want) {
			t.Fatal("committed reply was followed by an initial ICMP failure or lost its final error")
		}
	})
	t.Run("partial_first_batch_after_upstream_reply", func(t *testing.T) {
		conn := &udpFeedbackBatchConn{udpFeedbackCountConn: &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}, failure: want}
		adapter := newPacketTestAdapter(t, conn, false)
		packets := buf.MultiBuffer{xrayPacket(t, []byte("one")), xrayPacket(t, []byte("two")), xrayPacket(t, []byte("three"))}
		if err := adapter.WriteMultiBuffer(packets); !errors.Is(err, want) {
			t.Fatalf("partial batch: %v", err)
		}
		adapter.SubmitError(want)
		if conn.successes.Load() != 1 || conn.failures.Load() != 0 || len(conn.batches) != 1 || conn.batches[0] != 3 {
			t.Fatalf("upstream response lost its original batching or handshake: batches=%v", conn.batches)
		}
		for _, packet := range packets {
			if packet.Cap() != 0 {
				t.Fatal("partial batch retained an Xray buffer")
			}
		}
	})
}

func TestNativeUDPFailedFakeDNSLookupReportsOriginalTuple(t *testing.T) {
	const domain = "missing.native-feedback.test"
	config := memoryCoreConfig(nil)
	config.App = append(config.App, serial.ToTypedMessage(&appdns.Config{StaticHosts: []*appdns.Config_HostMapping{{
		Domain: udpFeedbackDomain(domain), ProxiedDomain: "#3", // Deterministic NXDOMAIN, no public DNS.
	}}}))
	config.Outbound[0].SenderSettings = serial.ToTypedMessage(&proxyman.SenderConfig{TargetStrategy: internet.DomainStrategy_FORCE_IP4})
	fixture := newUDPFeedbackCore(t, config, session.SniffingRequest{
		Enabled: true, MetadataOnly: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"fakedns"},
	})
	engine := fixture.instance.GetFeature((*dnsfeature.FakeDNSEngine)(nil)).(dnsfeature.FakeDNSEngine)
	ips := engine.GetFakeIPForDomain(domain)
	if len(ips) != 1 || !ips[0].Family().IsIPv4() {
		t.Fatal("FakeDNS did not allocate its IPv4 mapping")
	}
	original := udpFeedbackPacket(32123, []byte("unresolvable fake destination"))
	copy(original[16:20], ips[0].IP().To4())
	original[10], original[11] = 0, 0
	binary.BigEndian.PutUint16(original[10:12], udpFeedbackChecksum(original[:20]))
	var previous *udpFeedbackFlow
	for range 2 {
		flow := fixture.inject(t, original)
		if flow == previous {
			t.Fatal("closed NAT association was reused for the retry")
		}
		previous = flow
		select {
		case err := <-flow.closed:
			if err == nil || !strings.Contains(err.Error(), "failed to resolve ip for target "+domain) {
				t.Fatalf("lookup failure was not returned to the originator: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("failed target lookup did not release its NAT association")
		}
		select {
		case reply := <-fixture.output:
			assertUDPFeedbackICMP(t, reply, original)
		case <-time.After(time.Second):
			t.Fatal("failed fake-IP lookup did not report an ICMP error")
		}
	}
}

func TestNativeUDPRealDNSReplyCommitsHandshake(t *testing.T) {
	const domain = "answer.native-feedback.test"
	address := []byte{203, 0, 113, 45}
	config := memoryCoreConfig([]*router.RoutingRule{{
		TargetTag: &router.RoutingRule_Tag{Tag: "dns-out"},
		PortList:  &xnet.PortList{Range: []*xnet.PortRange{{From: 53, To: 53}}},
	}})
	config.App = append(config.App, serial.ToTypedMessage(&appdns.Config{StaticHosts: []*appdns.Config_HostMapping{{
		Domain: udpFeedbackDomain(domain), Ip: [][]byte{address},
	}}}))
	config.Outbound = append(config.Outbound, &core.OutboundHandlerConfig{Tag: "dns-out", ProxySettings: serial.ToTypedMessage(&proxydns.Config{})})
	fixture := newUDPFeedbackCore(t, config, session.SniffingRequest{})
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatal(err)
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	original := udpFeedbackPacket(53, payload)
	flow := fixture.inject(t, original)
	select {
	case packet := <-fixture.output:
		if len(packet) < 28 || packet[9] != 17 || !bytes.Equal(packet[12:16], original[16:20]) || binary.BigEndian.Uint16(packet[20:22]) != 53 {
			t.Fatalf("DNS reply lost its original server address: %x", packet)
		}
		var answer dnsmessage.Message
		if err := answer.Unpack(packet[28:]); err != nil {
			t.Fatal(err)
		}
		if answer.ID != query.ID || !answer.Response || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 1 {
			t.Fatalf("invalid real DNS reply: %+v", answer)
		}
		a, ok := answer.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || !bytes.Equal(a.A[:], address) {
			t.Fatalf("wrong DNS answer: %+v", answer.Answers)
		}
	case <-time.After(time.Second):
		t.Fatal("native DNS reply timed out")
	}
	select {
	case err := <-flow.committed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("real DNS response did not clear its handshake snapshot")
	}
	if err := flow.failure.HandshakeFailure(errors.New("late DNS failure probe")); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("successful DNS retained its request snapshot: %v", err)
	}
}

func udpFeedbackDomain(domain string) *geodata.DomainRule {
	return &geodata.DomainRule{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: domain}}}
}

func TestPacketHandshakeIgnoresShutdownAndPreservesTracker(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		cancelled bool
		feedback  bool
	}{
		{"eof", io.EOF, false, false},
		{"pipe", io.ErrClosedPipe, false, false},
		{"net_closed", net.ErrClosed, false, false},
		{"os_closed", os.ErrClosed, false, false},
		{"cancel", context.Canceled, false, false},
		{"live_outbound_deadline", context.DeadlineExceeded, false, true},
		{"live_os_deadline", os.ErrDeadlineExceeded, false, true},
		{"cancelled_context", errors.New("late failure"), true, false},
		{"deadline_after_cancel", context.DeadlineExceeded, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}
			adapter := newPacketTestAdapter(t, conn, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancelled {
				cancel()
			}
			forwarded := make(chan error, 2)
			adapter.errorContext = session.TrackedConnectionError(ctx, udpFeedbackTrackerFunc(func(err error) {
				// A reentrant originator must be called outside the packet IO lock.
				_ = adapter.dispatchError()
				forwarded <- err
			}))
			done := make(chan struct{})
			go func() { adapter.SubmitError(test.err); adapter.SubmitError(test.err); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("existing error tracker was called while holding the IO lock")
			}
			wantFeedback := uint32(0)
			if test.feedback {
				wantFeedback = 1
			}
			if conn.successes.Load() != 0 || conn.failures.Load() != wantFeedback || !errors.Is(adapter.dispatchError(), test.err) {
				t.Fatal("initial failure/shutdown classification or original error changed")
			}
			for range 2 {
				if <-forwarded != test.err {
					t.Fatal("existing originator's error was replaced")
				}
			}
		})
	}
}

func TestPacketHandshakeBoundaryConditions(t *testing.T) {
	t.Run("empty_multibuffer_does_not_establish_outbound", func(t *testing.T) {
		for _, emptyBuffer := range []bool{false, true} {
			conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}
			adapter := newPacketTestAdapter(t, conn, false)
			var packets buf.MultiBuffer
			if emptyBuffer {
				packets = buf.MultiBuffer{xrayPacket(t, nil)}
			}
			if err := adapter.WriteMultiBuffer(packets); err != nil {
				t.Fatal(err)
			}
			if conn.successes.Load() != 0 || conn.failures.Load() != 0 {
				t.Fatal("an empty upstream batch generated handshake feedback")
			}
			if emptyBuffer && packets[0].Cap() != 0 {
				t.Fatal("empty upstream batch retained its Xray buffer")
			}
			adapter.SubmitError(errors.New("outbound never established"))
			if conn.failures.Load() != 1 {
				t.Fatal("empty upstream batch suppressed a later initial failure")
			}
		}
	})
	t.Run("first_local_write_failure_is_not_an_outbound_handshake_failure", func(t *testing.T) {
		want := errors.New("native packet delivery failed")
		conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}
		conn.onWrite = func(*sbuf.Buffer, M.Socksaddr) error {
			if conn.successes.Load() != 1 {
				t.Error("native write started before upstream handshake success")
			}
			return want
		}
		adapter := newPacketTestAdapter(t, conn, false)
		packet := xrayPacket(t, []byte("upstream response"))
		if err := adapter.WriteMultiBuffer(buf.MultiBuffer{packet}); err != want {
			t.Fatalf("native delivery error = %v, want original error", err)
		}
		adapter.SubmitError(want)
		if packet.Cap() != 0 || conn.successes.Load() != 1 || conn.failures.Load() != 0 || adapter.dispatchError() != want {
			t.Fatal("local delivery failure leaked its buffer or generated an ICMP handshake failure")
		}
	})
	t.Run("invalid_failure_report_preserves_original_error", func(t *testing.T) {
		want := errors.New("original outbound failure")
		conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}, failureError: os.ErrInvalid}
		adapter := newPacketTestAdapter(t, conn, false)
		forwarded := make(chan error, 1)
		adapter.errorContext = session.TrackedConnectionError(context.Background(), udpFeedbackTrackerFunc(func(err error) {
			forwarded <- err
		}))
		adapter.SubmitError(want)
		if adapter.dispatchError() != want || conn.failures.Load() != 1 || conn.successes.Load() != 0 {
			t.Fatal("secondary handshake reporting error replaced the outbound failure")
		}
		select {
		case err := <-forwarded:
			if err != want {
				t.Fatal("parent tracker received a replacement error")
			}
		default:
			t.Fatal("original outbound error was not forwarded to its parent")
		}
	})
	t.Run("expired_parent_suppresses_deadline_feedback", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
		defer cancel()
		if ctx.Err() != context.DeadlineExceeded {
			t.Fatalf("parent was not expired: %v", ctx.Err())
		}
		conn := &udpFeedbackCountConn{nativePacketTestConn: &nativePacketTestConn{}}
		adapter := newPacketTestAdapter(t, conn, false)
		forwarded := make(chan error, 1)
		adapter.errorContext = session.TrackedConnectionError(ctx, udpFeedbackTrackerFunc(func(err error) {
			forwarded <- err
		}))
		adapter.SubmitError(context.DeadlineExceeded)
		if conn.failures.Load() != 0 || conn.successes.Load() != 0 || adapter.dispatchError() != context.DeadlineExceeded {
			t.Fatal("an already expired parent emitted handshake feedback or lost its deadline error")
		}
		select {
		case err := <-forwarded:
			if err != context.DeadlineExceeded {
				t.Fatal("expired parent's original deadline error was not forwarded")
			}
		default:
			t.Fatal("expired parent's deadline error was not forwarded")
		}
	})
}

type udpFeedbackTrackerFunc func(error)

func (f udpFeedbackTrackerFunc) SubmitError(err error) { f(err) }

type udpFeedbackCountConn struct {
	*nativePacketTestConn
	successes    atomic.Uint32
	failures     atomic.Uint32
	failureError error
}

func (c *udpFeedbackCountConn) HandshakeSuccess() error { c.successes.Add(1); return nil }
func (c *udpFeedbackCountConn) HandshakeFailure(error) error {
	c.failures.Add(1)
	return c.failureError
}

type udpFeedbackBatchConn struct {
	*udpFeedbackCountConn
	batches []int
	failure error
}

func (c *udpFeedbackBatchConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) { return c, true }

func (c *udpFeedbackBatchConn) WritePacketBatch(packets []*sbuf.Buffer, _ []M.Socksaddr) error {
	defer sbuf.ReleaseMulti(packets)
	c.batches = append(c.batches, len(packets))
	return c.failure
}

// The local verified TLS fixture uses the same Vision flow and UDP/443 policy
// in both cases. No QUIC implementation or public server is involved. The
// explicit control invokes only Sing's existing handshake API, in this test.
func TestNativeUDPRejected443HandshakeFeedback(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "native"
		if explicit {
			name = "explicit_sing_api_control"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newUDPFeedbackFixture(t)
			original := udpFeedbackPacket(443, []byte("rejected UDP/443"))
			flow := fixture.inject(t, original)
			var closedErr error
			select {
			case closedErr = <-flow.closed:
			case <-time.After(2 * time.Second):
				t.Fatal("VLESS rejection did not close the native packet flow")
			}
			actualErr := closedErr
			select {
			case actualErr = <-flow.reported:
			default:
			}
			if actualErr == nil || !strings.Contains(actualErr.Error(), "XTLS rejected UDP/443 traffic") {
				t.Fatalf("flow did not encounter the real VLESS UDP/443 rejection: %v", actualErr)
			}
			if explicit {
				// The original NAT connection still exposes the retained first
				// packet snapshot after ordinary Close. Calling onClose(err)
				// alone is not the operation that generates this ICMP response.
				err := flow.failure.HandshakeFailure(actualErr)
				if err != nil && !errors.Is(err, os.ErrInvalid) {
					t.Fatal(err)
				}
			} else if closedErr == nil || !strings.Contains(closedErr.Error(), "XTLS rejected UDP/443 traffic") {
				t.Errorf("onClose lost the outbound rejection: %v", closedErr)
			}
			select {
			case reply := <-fixture.output:
				assertUDPFeedbackICMP(t, reply, original)
			case <-time.After(time.Second):
				t.Fatal("rejected UDP/443 produced no local ICMP unreachable")
			}
		})
	}
}

func TestNativeUDPRejected443IPv6Feedback(t *testing.T) {
	fixture := newUDPFeedbackFixture(t)
	original := udpFeedbackPacket6(443, []byte("rejected IPv6 UDP/443"))
	flow := fixture.inject(t, original)
	select {
	case err := <-flow.closed:
		if err == nil || !strings.Contains(err.Error(), "XTLS rejected UDP/443 traffic") {
			t.Fatalf("IPv6 rejection was not returned to its originator: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("IPv6 VLESS rejection did not release the packet flow")
	}
	select {
	case reply := <-fixture.output:
		assertUDPFeedbackICMP(t, reply, original)
	case <-time.After(time.Second):
		t.Fatal("IPv6 rejection did not return ICMPv6 no-route")
	}
	if err := flow.failure.HandshakeFailure(errors.New("duplicate rejection probe")); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("rejected IPv6 request retained its snapshot: %v", err)
	}
}

// A successful packet must commit the handshake and discard the initial IP
// snapshot. Otherwise a later failure can quote an already successful request.
func TestNativeUDPSuccessReleasesHandshakeSnapshot(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "native"
		if explicit {
			name = "explicit_sing_api_control"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newUDPFeedbackFixture(t)
			port := echoUDP(t)
			payload := []byte("successful UDP handshake")
			flow := fixture.inject(t, udpFeedbackPacket(uint16(port), payload))
			select {
			case reply := <-fixture.output:
				if len(reply) < 28 || reply[9] != 17 || !bytes.Equal(reply[28:], payload) {
					t.Fatalf("VLESS UDP did not return its successful echo: %x", reply)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("VLESS UDP echo timed out")
			}
			if explicit {
				if err := flow.success.HandshakeSuccess(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-flow.committed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Error("successful reply did not report handshake success")
			}
			// This test-only probe is invalid after HandshakeSuccess. It proves
			// snapshot release without reflection or access to engine internals.
			if err := flow.failure.HandshakeFailure(errors.New("late test-only failure")); !errors.Is(err, os.ErrInvalid) {
				t.Errorf("successful native UDP retained its first-packet snapshot: %v", err)
			}
			select {
			case packet := <-fixture.output:
				t.Errorf("test-only failure probe replayed a retained successful request: %x", packet)
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}

type udpFeedbackFixture struct {
	instance *core.Instance
	device   *stun.MemoryTun
	flows    chan *udpFeedbackFlow
	output   chan []byte
}

func newUDPFeedbackFixture(t *testing.T) *udpFeedbackFixture {
	t.Helper()
	vision := visionCoreConfig(t)
	return newUDPFeedbackCore(t, vision.Config, session.SniffingRequest{})
}

func newUDPFeedbackCore(t *testing.T, config *core.Config, sniff session.SniffingRequest) *udpFeedbackFixture {
	t.Helper()
	instance, native := memoryCore(t, config, sniff)
	fixture := &udpFeedbackFixture{instance: instance, flows: make(chan *udpFeedbackFlow, 1), output: make(chan []byte, 8)}
	fixture.device = stun.NewMemoryTun(stun.MemoryTunOptions{MTU: 1500, Outbound: func(packets []*sbuf.Buffer) {
		for _, packet := range packets {
			copy := bytes.Clone(packet.Bytes())
			packet.Release()
			select {
			case fixture.output <- copy:
			default:
			}
		}
	}})
	ctx, cancel := context.WithCancel(native.ctx)
	gate := &flowHandler{native: native.native, mtu: 1500}
	handler := &udpFeedbackHandler{flowHandler: gate, accepted: fixture.flows}
	stack, err := stun.NewGo(stun.StackOptions{
		Context: ctx, Tun: fixture.device, TunOptions: native.options(), Handler: handler,
		Logger: native.options().Logger, UDPTimeout: time.Minute,
		UDPMapping: stun.NATMappingAddressAndPortDependent,
	})
	if err != nil {
		cancel()
		_ = fixture.device.Close()
		t.Fatal(err)
	}
	native.run = &stackSession{stack: stack, device: fixture.device, flows: gate, cancel: cancel}
	t.Cleanup(func() { _ = native.Close() })
	if err := fixture.device.Start(); err != nil {
		t.Fatal(err)
	}
	if err := stack.Start(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *udpFeedbackFixture) inject(t *testing.T, packet []byte) *udpFeedbackFlow {
	t.Helper()
	if _, err := f.device.Write(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case flow := <-f.flows:
		return flow
	case <-time.After(time.Second):
		t.Fatal("packet did not reach the native adapter")
		return nil
	}
}

type udpFeedbackHandler struct {
	*flowHandler
	accepted chan *udpFeedbackFlow
}

func (h *udpFeedbackHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	failure, failureOK := scommon.Cast[N.HandshakeFailure](conn)
	success, successOK := scommon.Cast[N.HandshakeSuccess](conn)
	if !failureOK || !successOK {
		panic("native UDP connection does not expose Sing handshake feedback")
	}
	flow := &udpFeedbackFlow{failure: failure, reported: make(chan error, 1), closed: make(chan error, 1), committed: make(chan error, 1)}
	observed := &udpFeedbackObservedConn{PacketConn: conn, PacketReadWaiter: conn.(N.PacketReadWaiter), success: success, committed: flow.committed}
	flow.success = observed
	h.accepted <- flow
	// Observe the existing outbound error hook without adding production error
	// propagation or calling a handshake method on behalf of the native adapter.
	ctx = session.TrackedConnectionError(ctx, flow)
	h.flowHandler.NewPacketConnectionEx(ctx, observed, source, destination, func(err error) {
		if onClose != nil {
			onClose(err)
		}
		flow.closed <- err
	})
}

type udpFeedbackFlow struct {
	failure   N.HandshakeFailure
	success   N.HandshakeSuccess
	reported  chan error
	closed    chan error
	committed chan error
}

// Preserve the original wait/batch/headroom capabilities while observing the
// success callback, so the snapshot probe cannot race an unfinished reply.
type udpFeedbackObservedConn struct {
	N.PacketConn
	N.PacketReadWaiter
	success   N.HandshakeSuccess
	committed chan error
}

func (c *udpFeedbackObservedConn) Upstream() any { return c.PacketConn }
func (c *udpFeedbackObservedConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return bufio.CreatePacketBatchWriter(c.PacketConn)
}

func (c *udpFeedbackObservedConn) HandshakeSuccess() error {
	err := c.success.HandshakeSuccess()
	select {
	case c.committed <- err:
	default:
	}
	return err
}

func (f *udpFeedbackFlow) SubmitError(err error) {
	select {
	case f.reported <- err:
	default:
	}
}

func udpFeedbackPacket(port uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	source, destination := netip.MustParseAddr("10.10.14.1").As4(), netip.MustParseAddr("192.0.2.90").As4()
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[10:12], udpFeedbackChecksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:22], 33001)
	binary.BigEndian.PutUint16(packet[22:24], port)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet // A zero UDP checksum is valid for this IPv4 control.
}

func udpFeedbackPacket6(port uint16, payload []byte) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload)))
	source, destination := netip.MustParseAddr("fc00::1").As16(), netip.MustParseAddr("2001:db8::90").As16()
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	binary.BigEndian.PutUint16(packet[40:42], 33001)
	binary.BigEndian.PutUint16(packet[42:44], port)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload)))
	copy(packet[48:], payload)
	checksum := udpFeedbackIPv6Checksum(packet, 17)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:48], checksum)
	return packet
}

func udpFeedbackIPv6Checksum(packet []byte, protocol byte) uint16 {
	pseudo := make([]byte, 40+len(packet)-40)
	copy(pseudo[:32], packet[8:40])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(packet)-40))
	pseudo[39] = protocol
	copy(pseudo[40:], packet[40:])
	return udpFeedbackChecksum(pseudo)
}

func udpFeedbackChecksum(packet []byte) uint16 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet))
		packet = packet[2:]
	}
	if len(packet) != 0 {
		sum += uint32(packet[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func assertUDPFeedbackICMP(t *testing.T, reply, original []byte) {
	t.Helper()
	if original[0]>>4 == 6 {
		if len(reply) < 96 || reply[0]>>4 != 6 || reply[6] != 58 || reply[40] != 1 || reply[41] != 0 {
			t.Fatalf("expected IPv6 ICMP no-route, got %x", reply)
		}
		if udpFeedbackIPv6Checksum(reply, 58) != 0 || !bytes.Equal(reply[8:24], original[24:40]) ||
			!bytes.Equal(reply[24:40], original[8:24]) || !bytes.Equal(reply[48:96], original[:48]) {
			t.Fatalf("invalid ICMPv6 checksum or original UDP tuple: %x", reply)
		}
		return
	}
	if len(reply) < 56 || reply[0] != 0x45 || reply[9] != 1 || reply[20] != 3 || reply[21] != 1 {
		t.Fatalf("expected IPv4 ICMP host unreachable, got %x", reply)
	}
	if udpFeedbackChecksum(reply[:20]) != 0 || udpFeedbackChecksum(reply[20:]) != 0 {
		t.Fatalf("invalid ICMP/IP checksum: %x", reply)
	}
	if !bytes.Equal(reply[12:16], original[16:20]) || !bytes.Equal(reply[16:20], original[12:16]) || !bytes.Equal(reply[28:56], original[:28]) {
		t.Fatalf("ICMP did not quote the original rejected UDP tuple: %x", reply)
	}
}
