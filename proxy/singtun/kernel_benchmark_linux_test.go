//go:build with_sing_tun && linux && !android

package singtun

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	stun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	singsocks "github.com/sagernet/sing/protocol/socks"
	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/buf"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	xsocks "github.com/xtls/xray-core/proxy/socks"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// BenchmarkKernelNativeEchoDuplex measures steady-state, single-connection
// IPv4 application echo over an actual MTU-1500 Linux TUN. SetBytes counts upload
// plus echoed download; the MB/s number is aggregate duplex throughput, not a
// one-direction download rate. Setup, handshakes, warmup and teardown are excluded.
// Allocations and getrusage(RUSAGE_SELF) include all participating Go threads,
// Xray cores, loopback application server and the local Vision node. They do not
// represent whole-host CPU, Android power use or an external-network benchmark.
func BenchmarkKernelNativeEchoDuplex(b *testing.B) {
	for _, profile := range []string{"freedom", "vision_tls13"} {
		b.Run(profile, func(b *testing.B) {
			b.StopTimer()
			config := memoryCoreConfig(nil)
			var applicationTLS *tls.Config
			var port int
			if profile == "vision_tls13" {
				fixture := visionCoreConfig(b)
				config, applicationTLS, port = fixture.Config, fixture.ClientTLS, int(fixture.Target.Port())
			} else {
				port = echoTCP(b)
			}
			for _, mode := range []string{"socks_full_splice", "native_read_write", "native_download_splice"} {
				b.Run(mode, func(b *testing.B) {
					benchmarkKernelEchoMode(b, mode, proto.Clone(config).(*core.Config), port, applicationTLS)
				})
			}
		})
	}
}

func benchmarkKernelEchoMode(b *testing.B, mode string, config *core.Config, port int, applicationTLS *tls.Config) {
	b.Helper()
	b.StopTimer()
	// Xray's log handler is shared by cores in this process. The client logger
	// therefore also suppresses the fixture node's logs during bulk transfer.
	// Put it first so core initialization cannot leave the default debug logger.
	config.App = append([]*serial.TypedMessage{serial.ToTypedMessage(&applog.Config{
		ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None, ErrorLogLevel: clog.Severity_Error,
	})}, config.App...)
	_, name, ip4, ip6 := kernelDevice(b)
	var socksForwarder *kernelBenchmarkSOCKS
	var ordinaryForwarder *kernelBenchmarkOrdinary
	var instance *core.Instance
	switch mode {
	case "socks_full_splice":
		socksPort := visionLoopbackPort(b)
		config.Inbound = []*core.InboundHandlerConfig{{
			Tag: integrationTag,
			ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
				Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
				PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(socksPort), To: uint32(socksPort)}}},
			}),
			ProxySettings: serial.ToTypedMessage(&xsocks.ServerConfig{AuthType: xsocks.AuthType_NO_AUTH, UserLevel: 7}),
		}}
		created, err := core.New(config)
		if err != nil {
			b.Fatal(err)
		}
		instance = created
		b.Cleanup(func() { _ = instance.Close() })
		if err = instance.Start(); err != nil {
			b.Fatal(err)
		}
		socksForwarder = &kernelBenchmarkSOCKS{
			flowHandler: &flowHandler{},
			client: singsocks.NewClient(&kernelBenchmarkLoopbackDialer{dialer: net.Dialer{Timeout: 5 * time.Second}},
				M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1"), Port: uint16(socksPort)}, singsocks.Version5, "", ""),
		}
		benchmarkKernelStack(b, name, ip4, ip6, context.Background(), socksForwarder, socksForwarder.flowHandler)
	case "native_read_write":
		created, handler := memoryCore(b, config, session.SniffingRequest{})
		instance = created
		ordinaryForwarder = &kernelBenchmarkOrdinary{flowHandler: &flowHandler{native: handler.native, mtu: 1500}}
		benchmarkKernelStack(b, name, ip4, ip6, handler.ctx, ordinaryForwarder, ordinaryForwarder.flowHandler)
	case "native_download_splice":
		instance = kernelCore(b, config, name, ip4, ip6)
	default:
		b.Fatalf("unknown benchmark mode %q", mode)
	}
	raw := kernelDial(b, ip4, port)
	var conn net.Conn = raw
	if applicationTLS != nil {
		quiet, ok := instance.GetFeature((*applog.Instance)(nil)).(*applog.Instance)
		if !ok {
			b.Fatal("benchmark core has no quiet logger")
		}
		// Observe protocol output only while warming up. No readiness state is
		// written or sampled across goroutines. Restore the known core-owned
		// logger before any bulk transfer, including on an early benchmark failure.
		probe := &kernelBenchmarkVisionProbe{}
		clog.RegisterHandler(probe)
		b.Cleanup(func() { clog.RegisterHandler(quiet) })
		secure := tls.Client(raw, applicationTLS.Clone())
		if err := secure.Handshake(); err != nil {
			b.Fatal(err)
		}
		if state := secure.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
			b.Fatal("benchmark application did not establish verified TLS1.3")
		}
		conn = secure
		benchmarkVisionSmallRecords(b, conn, probe)
		clog.RegisterHandler(quiet)
	}
	payload := make([]byte, 4<<20)
	for index := range payload {
		payload[index] = byte(index*31 + index>>11)
	}
	received := make([]byte, len(payload))
	commands, results := make(chan struct{}), make(chan error, 1)
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			case <-commands:
			}
			err := benchmarkWriteAll(conn, payload)
			select {
			case results <- err:
			case <-stop:
				return
			}
		}
	}()
	b.Cleanup(func() {
		close(stop)
		_ = raw.SetDeadline(time.Now())
		_ = raw.Close()
		writer.Wait()
	})
	transfer := func() error {
		if err := raw.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return err
		}
		commands <- struct{}{}
		if _, err := io.ReadFull(conn, received); err != nil {
			return err
		}
		return <-results
	}
	if err := transfer(); err != nil || !bytes.Equal(received, payload) {
		b.Fatalf("warmup echo failed: %v", err)
	}
	switch mode {
	case "socks_full_splice":
		if socksForwarder.spliced.Load() != 1 {
			b.Fatalf("SOCKS baseline did not use NewGo full Splice: %v", socksForwarder.failure())
		}
	case "native_read_write":
		if ordinaryForwarder.connections.Load() != 1 {
			b.Fatal("ordinary native Read/Write adapter was not used")
		}
	case "native_download_splice":
		assertNativeHandoff(b)
	}
	var before, after unix.Rusage
	b.ReportAllocs()
	b.SetBytes(int64(2 * len(payload)))
	b.ResetTimer()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &before); err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for range b.N {
		if err := transfer(); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err != nil {
		b.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		b.Fatal("measured echo payload differs")
	}
	user := benchmarkTimevalSeconds(after.Utime) - benchmarkTimevalSeconds(before.Utime)
	system := benchmarkTimevalSeconds(after.Stime) - benchmarkTimevalSeconds(before.Stime)
	b.ReportMetric(user*1000/float64(b.N), "user-ms/op")
	b.ReportMetric(system*1000/float64(b.N), "sys-ms/op")
	b.ReportMetric((user+system)*1000/float64(b.N), "cpu-ms/op")
	if user+system > 0 {
		b.ReportMetric(float64(2*len(payload))*float64(b.N)/1e6/(user+system), "MB/cpu-s")
	}
}

// A large first application write can keep Vision padding active because its
// records span many source buffers. Small complete TLS application records let
// the genuine state machine negotiate its direct phase before the bulk workload.
func benchmarkVisionSmallRecords(t testing.TB, conn net.Conn, probe *kernelBenchmarkVisionProbe) {
	t.Helper()
	for index, size := range []int{1, 37, 1, 37} {
		payload := bytes.Repeat([]byte{byte(index + 31)}, size)
		if err := benchmarkWriteAll(conn, payload); err != nil {
			t.Fatal("Vision small-record warmup write: ", err)
		}
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, actual); err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("Vision small-record warmup %d: payload=%x, err=%v", size, actual, err)
		}
	}
	if probe.tls13.Load() < 2 || probe.direct.Load() < 2 {
		t.Fatalf("Vision did not complete its genuine bidirectional direct transition: TLS1.3 observations=%d, command-2 receipts=%d",
			probe.tls13.Load(), probe.direct.Load())
	}
}

// This temporary, silent warmup observer records the two real Vision peers'
// TLS detection and padding-direct receipts. It is removed before bulk warmup
// and measurement, so debug message construction is also outside measured CPU.
type kernelBenchmarkVisionProbe struct {
	tls13  atomic.Uint32
	direct atomic.Uint32
}

func (*kernelBenchmarkVisionProbe) Severity() clog.Severity { return clog.Severity_Debug }

func (p *kernelBenchmarkVisionProbe) Handle(message clog.Message) {
	general, ok := message.(*clog.GeneralMessage)
	if !ok || general.Severity != clog.Severity_Debug {
		return
	}
	text := general.String()
	if strings.Contains(text, "XtlsFilterTls found tls 1.3!") {
		p.tls13.Add(1)
	}
	if strings.Contains(text, "Xtls Unpadding new block,") && strings.HasSuffix(text, " command 2") {
		p.direct.Add(1)
	}
}

func benchmarkWriteAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		payload = payload[n:]
	}
	return nil
}

func benchmarkTimevalSeconds(value unix.Timeval) float64 {
	return float64(value.Sec) + float64(value.Usec)/1e6
}

func benchmarkKernelStack(b *testing.B, name string, ip4, ip6 netip.Addr, parent context.Context, handler stun.Handler, gate *flowHandler) {
	b.Helper()
	options := stun.Options{
		Name: name, MTU: 1500, DNSMode: stun.DNSModeDisabled, EXP_ExternalConfiguration: true, Logger: logger.NOP(),
		Inet4Address: []netip.Prefix{netip.PrefixFrom(ip4, 30)}, Inet6Address: []netip.Prefix{netip.PrefixFrom(ip6, 126)},
	}
	device, err := openDevice(&options)
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(parent)
	stack, err := stun.NewGo(stun.StackOptions{
		Context: ctx, Tun: device, TunOptions: options, Handler: handler,
		Logger: logger.NOP(), UDPTimeout: time.Minute, ICMPTimeout: 10 * time.Second,
		UDPMapping: stun.NATMappingAddressAndPortDependent,
	})
	cleanup := func() {
		gate.stop()
		cancel()
		if stack != nil {
			_ = stack.Close()
		}
		gate.wg.Wait()
		_ = device.Close()
	}
	b.Cleanup(cleanup)
	if err == nil {
		err = device.Start()
	}
	if err == nil {
		err = stack.Start()
	}
	if err != nil {
		b.Fatal(err)
	}
}

// The ordinary comparison hides only optional methods from the production TCP
// wrapper. Its Read, Write, addresses, cancellation and core dispatch stay the same.
type kernelBenchmarkPlainConn struct {
	net.Conn
	writer buf.Writer
}

func (c *kernelBenchmarkPlainConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return c.writer.WriteMultiBuffer(mb)
}

type kernelBenchmarkOrdinary struct {
	*flowHandler
	connections atomic.Uint64
}

func (h *kernelBenchmarkOrdinary) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !h.begin() {
		rejectConnection(conn, onClose)
		return
	}
	defer h.wg.Done()
	err := N.ReportHandshakeSuccess(conn)
	if err == nil {
		native, ok := conn.(*stun.GoConn)
		if !ok {
			err = errors.New("ordinary benchmark did not receive GoConn")
		} else {
			wrapped := &tcpConn{GoConn: native, source: source.TCPAddr(), destination: destination.TCPAddr()}
			h.connections.Add(1)
			h.native.HandleConnectionContext(ctx, &kernelBenchmarkPlainConn{Conn: wrapped, writer: wrapped}, toDestination(destination, xnet.Network_TCP))
		}
	}
	if err != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(err)
	}
}

// This test-only TCP baseline mirrors the existing Android controller's SOCKS
// handshake and full-Splice ownership adapter. It never dials remote targets:
// the only OS socket opened here is the loopback Xray SOCKS listener.
type kernelBenchmarkSOCKS struct {
	*flowHandler
	client  N.Dialer
	spliced atomic.Uint64
	errMu   sync.Mutex
	err     error
}

func (*kernelBenchmarkSOCKS) JudgeFlow(protocol uint8, _, _ netip.AddrPort, _ []byte) stun.FlowVerdict {
	if protocol == 6 {
		return stun.FlowVerdict{Action: stun.ActionAccept}
	}
	return stun.FlowVerdict{Action: stun.ActionReject}
}

func (h *kernelBenchmarkSOCKS) NewConnectionEx(ctx context.Context, conn net.Conn, _, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !h.begin() {
		rejectConnection(conn, onClose)
		return
	}
	var once sync.Once
	finish := func(err error) {
		once.Do(func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(err)
			}
			h.wg.Done()
		})
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	remote, err := h.client.DialContext(dialCtx, N.NetworkTCP, destination)
	cancel()
	if err == nil {
		err = N.ReportHandshakeSuccess(conn)
	}
	if err == nil {
		source, sourceOK := conn.(*stun.GoConn)
		socket, socketOK := remote.(*net.TCPConn)
		if sourceOK && socketOK && source.Splice(&kernelBenchmarkSpliceSocket{Conn: socket, original: socket}, stun.SpliceOptions{OnClose: finish}) {
			h.spliced.Add(1)
			return
		}
		err = errors.New("SOCKS benchmark requires successful NewGo full Splice")
	}
	if remote != nil {
		_ = remote.Close()
	}
	h.errMu.Lock()
	h.err = err
	h.errMu.Unlock()
	finish(err)
}

func (*kernelBenchmarkSOCKS) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	rejectConnection(conn, onClose)
}

func (h *kernelBenchmarkSOCKS) failure() error {
	h.errMu.Lock()
	defer h.errMu.Unlock()
	return h.err
}

type kernelBenchmarkLoopbackDialer struct{ dialer net.Dialer }

func (d *kernelBenchmarkLoopbackDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsLoopback() {
		return nil, fmt.Errorf("benchmark adapter refused non-loopback SOCKS listener %s", destination)
	}
	return d.dialer.DialContext(ctx, network, destination.String())
}

func (*kernelBenchmarkLoopbackDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("benchmark is TCP-only")
}

type kernelBenchmarkSpliceSocket struct {
	syscall.Conn
	original   io.Closer
	mu         sync.Mutex
	attachment io.Closer
	closed     bool
}

func (s *kernelBenchmarkSpliceSocket) Attach(owner io.Closer) (io.Closer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.attachment != nil {
		return nil, false
	}
	s.attachment = owner
	return s.original, true
}

func (s *kernelBenchmarkSpliceSocket) Detach() {
	s.mu.Lock()
	s.attachment = nil
	closed := s.closed
	s.mu.Unlock()
	if closed {
		_ = s.original.Close()
	}
}

func (s *kernelBenchmarkSpliceSocket) Close() error {
	s.mu.Lock()
	s.closed = true
	owner := s.attachment
	s.mu.Unlock()
	if owner != nil {
		return owner.Close()
	}
	return s.original.Close()
}
