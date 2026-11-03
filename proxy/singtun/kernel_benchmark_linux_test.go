//go:build with_sing_tun && linux && !android

package singtun

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
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

const kernelBenchmarkPayloadSize = 4 << 20

// BenchmarkKernelNativeEchoDuplex measures steady-state, single-connection
// IPv4 application echo over an actual Linux TUN at each named MTU. SetBytes counts upload
// plus echoed download; the MB/s number is aggregate duplex throughput, not a
// one-direction download rate. Setup, handshakes, warmup and teardown are excluded.
// Allocations and getrusage(RUSAGE_SELF) include all participating Go threads,
// Xray cores, loopback application server and the local Vision node. HEV CPU
// additionally includes its child process; Go allocation counts exclude HEV's C
// heap and are not a total-memory comparison. These metrics do not
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
			for _, mtu := range []int{1500, 9000} {
				b.Run(fmt.Sprintf("mtu_%d", mtu), func(b *testing.B) {
					for _, mode := range []string{"hev_android_defaults", "hev_no_jumbo", "socks_full_splice", "native_read_write", "native_download_splice"} {
						b.Run(mode, func(b *testing.B) {
							benchmarkKernelEchoMode(b, mode, "duplex", mtu, proto.Clone(config).(*core.Config), port, applicationTLS, profile == "vision_tls13")
						})
					}
				})
			}
		})
	}
}

// BenchmarkKernelNativeProfile is a manual diagnostic matrix. The ordinary CI
// selects BenchmarkKernelNativeEchoDuplex explicitly, keeping its 60-row baseline.
// One-way cases count only their bulk direction; the one-byte command/completion
// messages are excluded from SetBytes. Profiling is opt-in and starts after warmup.
func BenchmarkKernelNativeProfile(b *testing.B) {
	for _, transport := range []string{"freedom", "freedom_tls13", "vision_tls13"} {
		b.Run(transport, func(b *testing.B) {
			for _, workload := range []string{"duplex", "upload", "download"} {
				b.Run(workload, func(b *testing.B) {
					b.StopTimer()
					config := memoryCoreConfig(nil)
					var applicationTLS *tls.Config
					var application []func(net.Conn) (int64, error)
					if workload != "duplex" {
						application = append(application, func(conn net.Conn) (int64, error) {
							return benchmarkKernelOneWayServer(conn, workload)
						})
					}
					var port int
					if transport == "vision_tls13" {
						fixture := visionCoreConfig(b, application...)
						config, applicationTLS, port = fixture.Config, fixture.ClientTLS, int(fixture.Target.Port())
					} else if transport == "freedom_tls13" {
						ca, _, _, cert, key := visionCertificates(b)
						port, applicationTLS, _ = visionTLSApplication(b, ca, cert, key, application...)
					} else if len(application) == 0 {
						port = echoTCP(b)
					} else {
						port = serveTCP(b, func(conn net.Conn) { _, _ = application[0](conn) })
					}
					b.Run("mtu_9000", func(b *testing.B) {
						for _, mode := range kernelBenchmarkProfileModes(transport) {
							b.Run(mode, func(b *testing.B) {
								benchmarkKernelEchoMode(b, mode, workload, 9000, proto.Clone(config).(*core.Config), port, applicationTLS, transport == "vision_tls13")
							})
						}
					})
				})
			}
		})
	}
}

// Keep experimental path additions in this list until they merit baseline CI.
func kernelBenchmarkProfileModes(transport string) []string {
	modes := []string{"hev_android_defaults", "socks_full_splice", "socks_full_splice_jumbo", "native_read_write", "native_download_splice", "native_vector_write", "native_bidirectional_splice", "native_bidirectional_jumbo"}
	if transport == "freedom" {
		modes = append(modes, "sing_direct_engine")
	}
	return modes
}

func benchmarkKernelEchoMode(b *testing.B, mode, workload string, mtu int, config *core.Config, port int, applicationTLS *tls.Config, isVision bool) {
	b.Helper()
	b.StopTimer()
	// Xray's log handler is shared by cores in this process. The client logger
	// therefore also suppresses the fixture node's logs during bulk transfer.
	// Put it first so core initialization cannot leave the default debug logger.
	config.App = append([]*serial.TypedMessage{serial.ToTypedMessage(&applog.Config{
		ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None, ErrorLogLevel: clog.Severity_Error,
	})}, config.App...)
	fd, name, ip4, ip6 := kernelDeviceMTU(b, mtu)
	var hev *kernelHEVProcess
	var socksForwarder *kernelBenchmarkSOCKS
	var nativeForwarder *kernelBenchmarkNative
	var instance *core.Instance
	var jumboProbe *kernelBenchmarkPacketProbe
	if mode == "native_bidirectional_jumbo" || mode == "socks_full_splice_jumbo" {
		jumboProbe = benchmarkKernelPacketProbe(b, name, ip4)
	}
	switch mode {
	case "socks_full_splice", "socks_full_splice_jumbo", "hev_android_defaults", "hev_no_jumbo":
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
		if mode != "socks_full_splice" && mode != "socks_full_splice_jumbo" {
			hev = benchmarkStartHEV(b, fd, ip4, ip6, mtu, socksPort, mode == "hev_no_jumbo")
			break
		}
		socksForwarder = &kernelBenchmarkSOCKS{
			flowHandler: &flowHandler{},
			client: singsocks.NewClient(&kernelBenchmarkLoopbackDialer{dialer: net.Dialer{Timeout: 5 * time.Second}},
				M.Socksaddr{Addr: netip.MustParseAddr("127.0.0.1"), Port: uint16(socksPort)}, singsocks.Version5, "", ""),
		}
		stackConfig := &Config{TcpLocalJumbo: mode == "socks_full_splice_jumbo"}
		benchmarkKernelStack(b, name, ip4, ip6, mtu, stackConfig, context.Background(), socksForwarder, socksForwarder.flowHandler)
	case "native_read_write", "native_download_splice", "native_vector_write", "native_bidirectional_splice", "native_bidirectional_jumbo":
		created, handler := memoryCore(b, config, session.SniffingRequest{})
		instance = created
		handler.config.TcpLocalJumbo = mode == "native_bidirectional_jumbo"
		nativeForwarder = &kernelBenchmarkNative{flowHandler: &flowHandler{native: handler.native, mtu: mtu}, mode: mode}
		benchmarkKernelStack(b, name, ip4, ip6, mtu, handler.config, handler.ctx, nativeForwarder, nativeForwarder.flowHandler)
	case "sing_direct_engine":
		socksForwarder = &kernelBenchmarkSOCKS{
			flowHandler: &flowHandler{},
			client:      &kernelBenchmarkDirectDialer{kernelBenchmarkLoopbackDialer{dialer: net.Dialer{Timeout: 5 * time.Second}}},
		}
		benchmarkKernelStack(b, name, ip4, ip6, mtu, nil, context.Background(), socksForwarder, socksForwarder.flowHandler)
	default:
		b.Fatalf("unknown benchmark mode %q", mode)
	}
	raw := kernelDial(b, ip4, port)
	// Verify the host route and negotiated local MSS actually changed. Merely
	// changing stack metadata would leave this a mismatched-MTU comparison.
	var pathMTU, mss int
	var queryErr error
	control, err := raw.SyscallConn()
	if err != nil {
		b.Fatal(err)
	}
	if err = control.Control(func(fd uintptr) {
		pathMTU, queryErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU)
		if queryErr == nil {
			mss, queryErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
		}
	}); err != nil {
		b.Fatal(err)
	}
	maxMSS := mtu - 40
	if mode == "hev_android_defaults" || mode == "hev_no_jumbo" {
		// APK-pinned lwIP advertises TCP_MSS=8191 even on a larger interface.
		// Retain that production limit and report its negotiated value.
		maxMSS = min(maxMSS, 8191)
	}
	if queryErr != nil || pathMTU != mtu || mss < maxMSS-20 || mss > maxMSS {
		b.Fatalf("MTU/MSS mismatch: requested=%d path=%d mss=%d error=%v", mtu, pathMTU, mss, queryErr)
	}
	var quiet *applog.Instance
	var probe *kernelBenchmarkVisionProbe
	if isVision {
		var ok bool
		quiet, ok = instance.GetFeature((*applog.Instance)(nil)).(*applog.Instance)
		if !ok {
			b.Fatal("benchmark core has no quiet logger")
		}
		// Observe only genuine Vision transitions. Direct TLS uses the same
		// application records without pretending to negotiate Vision padding.
		probe = &kernelBenchmarkVisionProbe{}
		clog.RegisterHandler(probe)
		b.Cleanup(func() { clog.RegisterHandler(quiet) })
	}
	var conn net.Conn = raw
	if applicationTLS != nil {
		secure := tls.Client(raw, applicationTLS.Clone())
		if err := secure.Handshake(); err != nil {
			b.Fatal(err)
		}
		if state := secure.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
			b.Fatal("benchmark application did not establish verified TLS1.3")
		}
		conn = secure
	}
	if probe != nil {
		benchmarkVisionSmallRecords(b, conn, probe)
		clog.RegisterHandler(quiet)
	} else if applicationTLS != nil || workload != "duplex" {
		benchmarkSmallRecords(b, conn)
	}
	transfer, verify, bytesPerOp := benchmarkKernelTraffic(b, raw, conn, workload)
	if err := transfer(); err != nil {
		b.Fatalf("warmup transfer failed: %v", err)
	}
	if err := verify(); err != nil {
		b.Fatalf("warmup validation failed: %v", err)
	}
	switch mode {
	case "socks_full_splice", "socks_full_splice_jumbo", "sing_direct_engine":
		if socksForwarder.spliced.Load() != 1 {
			b.Fatalf("%s did not use NewGo full Splice: %v", mode, socksForwarder.failure())
		}
	}
	if nativeForwarder != nil {
		nativeForwarder.assertHandoff(b)
	}
	if jumboProbe != nil {
		if workload == "upload" {
			// Upload completion replies contain only one byte. Exercise a
			// separate bulk receive before timing so the same above-MTU
			// packet assertion remains meaningful in this one-way case.
			benchmarkKernelJumboWarmup(b, conn)
		}
		if err := jumboProbe.stop(); err != nil {
			b.Fatal("local jumbo packet observation: ", err)
		}
		if jumboProbe.maxPacket.Load() <= uint32(mtu) {
			b.Fatalf("local jumbo did not emit a TCP packet larger than MTU %d (largest %d)", mtu, jumboProbe.maxPacket.Load())
		}
	}
	var rawUploadBefore, rawDownloadBefore int64
	if nativeForwarder != nil {
		rawUploadBefore, rawDownloadBefore = nativeForwarder.rawUpload.Load(), nativeForwarder.rawDownload.Load()
	}
	var before, after unix.Rusage
	var childUserBefore, childSystemBefore float64
	if hev != nil {
		childUserBefore, childSystemBefore = hev.cpuTime(b)
	}
	b.ReportAllocs()
	b.SetBytes(bytesPerOp)
	b.ResetTimer()
	b.ReportMetric(float64(pathMTU), "path-MTU")
	b.ReportMetric(float64(mss), "local-MSS")
	if jumboProbe != nil {
		b.ReportMetric(float64(jumboProbe.maxPacket.Load()), "jumbo-max-IP-B")
	}
	stopProfile := benchmarkKernelProfileStart(b)
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
	var rawUpload, rawDownload int64
	if nativeForwarder != nil {
		rawUpload = nativeForwarder.rawUpload.Load() - rawUploadBefore
		rawDownload = nativeForwarder.rawDownload.Load() - rawDownloadBefore
	}
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err != nil {
		b.Fatal(err)
	}
	user := benchmarkTimevalSeconds(after.Utime) - benchmarkTimevalSeconds(before.Utime)
	system := benchmarkTimevalSeconds(after.Stime) - benchmarkTimevalSeconds(before.Stime)
	if hev != nil {
		childUser, childSystem := hev.cpuTime(b)
		user += childUser - childUserBefore
		system += childSystem - childSystemBefore
		b.ReportMetric((childUser-childUserBefore+childSystem-childSystemBefore)*1000/float64(b.N), "hev-cpu-ms/op")
	}
	stopProfile()
	if err := verify(); err != nil {
		b.Fatal("measured payload validation: ", err)
	}
	if nativeForwarder != nil {
		b.ReportMetric(float64(rawUpload)/float64(b.N), "native-up-B/op")
		b.ReportMetric(float64(rawDownload)/float64(b.N), "native-down-B/op")
		// The final receiver has acknowledged each upload and read each
		// download. Progress must therefore cover the measured bulk bytes,
		// rather than merely an attempted capability probe during warmup.
		expected := int64(kernelBenchmarkPayloadSize) * int64(b.N)
		if nativeForwarder.uploadEnabled() && workload != "download" && rawUpload < expected {
			b.Fatalf("native upload handled %d bytes, expected at least %d", rawUpload, expected)
		}
		if nativeForwarder.downloadEnabled() && workload != "upload" && rawDownload < expected {
			b.Fatalf("native download handled %d bytes, expected at least %d", rawDownload, expected)
		}
	}
	b.ReportMetric(user*1000/float64(b.N), "user-ms/op")
	b.ReportMetric(system*1000/float64(b.N), "sys-ms/op")
	b.ReportMetric((user+system)*1000/float64(b.N), "cpu-ms/op")
	if user+system > 0 {
		b.ReportMetric(float64(bytesPerOp)*float64(b.N)/1e6/(user+system), "MB/cpu-s")
	}
}

func benchmarkKernelPayload() []byte {
	payload := make([]byte, kernelBenchmarkPayloadSize)
	for index := range payload {
		payload[index] = byte(index*31 + index>>11)
	}
	return payload
}

func benchmarkKernelJumboWarmup(b testing.TB, conn net.Conn) {
	b.Helper()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		b.Fatal(err)
	}
	if err := benchmarkWriteAll(conn, []byte{'j'}); err != nil {
		b.Fatal("jumbo receive warmup command: ", err)
	}
	payload := benchmarkKernelPayload()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, received); err != nil || !bytes.Equal(received, payload) {
		b.Fatalf("jumbo receive warmup payload: %v", err)
	}
}

func benchmarkKernelTraffic(b testing.TB, raw, conn net.Conn, workload string) (transfer, verify func() error, bytesPerOp int64) {
	b.Helper()
	payload := benchmarkKernelPayload()
	deadline := func() error { return raw.SetDeadline(time.Now().Add(30 * time.Second)) }
	if workload == "upload" {
		var ack [1]byte
		transfer = func() error {
			if err := deadline(); err != nil {
				return err
			}
			if err := benchmarkWriteAll(conn, []byte{'u'}); err != nil {
				return err
			}
			if err := benchmarkWriteAll(conn, payload); err != nil {
				return err
			}
			_, err := io.ReadFull(conn, ack[:])
			return err
		}
		verify = func() error {
			if err := deadline(); err != nil {
				return err
			}
			if err := benchmarkWriteAll(conn, []byte{'v'}); err != nil {
				return err
			}
			if _, err := io.ReadFull(conn, ack[:]); err != nil {
				return err
			}
			if ack[0] != 1 {
				return errors.New("server received different upload payload")
			}
			return nil
		}
		return transfer, verify, int64(len(payload))
	}
	received := make([]byte, len(payload))
	verify = func() error {
		if !bytes.Equal(received, payload) {
			return errors.New("received different download payload")
		}
		return nil
	}
	if workload == "download" {
		transfer = func() error {
			if err := deadline(); err != nil {
				return err
			}
			if err := benchmarkWriteAll(conn, []byte{'d'}); err != nil {
				return err
			}
			_, err := io.ReadFull(conn, received)
			return err
		}
		return transfer, verify, int64(len(payload))
	}
	if workload != "duplex" {
		b.Fatalf("unknown benchmark workload %q", workload)
	}
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
	transfer = func() error {
		if err := deadline(); err != nil {
			return err
		}
		commands <- struct{}{}
		if _, err := io.ReadFull(conn, received); err != nil {
			return err
		}
		return <-results
	}
	return transfer, verify, int64(2 * len(payload))
}

// The application echoes the same readiness records as the duplex Vision
// fixture, then transfers bulk data in one direction. Completion ACKs make
// uploads wait for the actual receiver instead of measuring socket buffering.
func benchmarkKernelOneWayServer(conn net.Conn, workload string) (int64, error) {
	payload := benchmarkKernelPayload()
	received := make([]byte, len(payload))
	for _, size := range []int{1, 37, 1, 37} {
		if _, err := io.ReadFull(conn, received[:size]); err != nil {
			return 0, err
		}
		if err := benchmarkWriteAll(conn, received[:size]); err != nil {
			return 0, err
		}
	}
	var total int64
	var command [1]byte
	for {
		if _, err := io.ReadFull(conn, command[:]); err != nil {
			return total, err
		}
		switch {
		case command[0] == 'u' && workload == "upload":
			if _, err := io.ReadFull(conn, received); err != nil {
				return total, err
			}
			total += int64(len(received))
			if err := benchmarkWriteAll(conn, []byte{1}); err != nil {
				return total, err
			}
		case command[0] == 'v' && workload == "upload":
			var valid byte
			if bytes.Equal(received, payload) {
				valid = 1
			}
			if err := benchmarkWriteAll(conn, []byte{valid}); err != nil {
				return total, err
			}
		case command[0] == 'j' || command[0] == 'd' && workload == "download":
			if err := benchmarkWriteAll(conn, payload); err != nil {
				return total, err
			}
			total += int64(len(payload))
		default:
			return total, fmt.Errorf("unexpected %q command for %s workload", command[0], workload)
		}
	}
}

func TestKernelBenchmarkOneWayProtocol(t *testing.T) {
	for _, workload := range []string{"upload", "download"} {
		t.Run(workload, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			type result struct {
				bytes int64
				err   error
			}
			done := make(chan result, 1)
			go func() {
				defer server.Close()
				bytes, err := benchmarkKernelOneWayServer(server, workload)
				done <- result{bytes, err}
			}()
			benchmarkSmallRecords(t, client)
			benchmarkKernelJumboWarmup(t, client)
			transfer, verify, bytesPerOp := benchmarkKernelTraffic(t, client, client, workload)
			if bytesPerOp != kernelBenchmarkPayloadSize {
				t.Fatalf("one-way SetBytes=%d", bytesPerOp)
			}
			for range 2 {
				if err := transfer(); err != nil {
					t.Fatal(err)
				}
				if err := verify(); err != nil {
					t.Fatal(err)
				}
			}
			_ = client.Close()
			got := <-done
			if got.bytes != 3*kernelBenchmarkPayloadSize || !errors.Is(got.err, io.EOF) {
				t.Fatalf("server result=%+v", got)
			}
		})
	}
	t.Run("corrupt_upload", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			_, _ = benchmarkKernelOneWayServer(server, "upload")
		}()
		benchmarkSmallRecords(t, client)
		_ = client.SetDeadline(time.Now().Add(5 * time.Second))
		payload := benchmarkKernelPayload()
		payload[len(payload)-1] ^= 1
		if err := benchmarkWriteAll(client, append([]byte{'u'}, payload...)); err != nil {
			t.Fatal(err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(client, ack[:]); err != nil {
			t.Fatal(err)
		}
		if err := benchmarkWriteAll(client, []byte{'v'}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, ack[:]); err != nil || ack[0] != 0 {
			t.Fatalf("corrupted payload accepted: ack=%d, err=%v", ack[0], err)
		}
		_ = client.Close()
		<-done
	})
}

// Each diagnostic process selects one case and one profiler. Calibration runs
// overwrite the same CPU/trace file; the final run is retained. Block records
// accumulate the measured calibration intervals for that same case. Go profiles
// exclude the HEV child, whose CPU remains included in the reported totals.
func benchmarkKernelProfileStart(b *testing.B) func() {
	b.Helper()
	kind := os.Getenv("XRAY_NATIVE_PROFILE")
	if kind == "" {
		return func() {}
	}
	directory := os.Getenv("XRAY_NATIVE_PROFILE_DIR")
	if directory == "" {
		b.Fatal("XRAY_NATIVE_PROFILE_DIR is required for profiling")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		b.Fatal(err)
	}
	extension := ".pprof"
	if kind == "trace" {
		extension = ".trace"
	}
	file, err := os.Create(filepath.Join(directory, kind+extension))
	if err != nil {
		b.Fatal(err)
	}
	var finish func()
	switch kind {
	case "cpu":
		err = pprof.StartCPUProfile(file)
		finish = pprof.StopCPUProfile
	case "block":
		runtime.SetBlockProfileRate(1)
		finish = func() {
			runtime.SetBlockProfileRate(0)
			if err := pprof.Lookup("block").WriteTo(file, 0); err != nil {
				b.Error(err)
			}
		}
	case "trace":
		err = trace.Start(file)
		finish = trace.Stop
	default:
		err = fmt.Errorf("unknown XRAY_NATIVE_PROFILE %q", kind)
	}
	if err != nil {
		_ = file.Close()
		b.Fatal(err)
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			finish()
			if err := file.Close(); err != nil {
				b.Error(err)
			}
		})
	}
	b.Cleanup(stop)
	return stop
}

// A large first application write can keep Vision padding active because its
// records span many source buffers. Small complete TLS application records let
// the genuine state machine negotiate its direct phase before the bulk workload.
func benchmarkVisionSmallRecords(t testing.TB, conn net.Conn, probe *kernelBenchmarkVisionProbe) {
	t.Helper()
	benchmarkSmallRecords(t, conn)
	if probe.tls13.Load() < 2 || probe.direct.Load() < 2 {
		t.Fatalf("Vision did not complete its genuine bidirectional direct transition: TLS1.3 observations=%d, command-2 receipts=%d",
			probe.tls13.Load(), probe.direct.Load())
	}
}

func benchmarkSmallRecords(t testing.TB, conn net.Conn) {
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

func benchmarkKernelStack(b testing.TB, name string, ip4, ip6 netip.Addr, mtu int, config *Config, parent context.Context, handler stun.Handler, gate *flowHandler) {
	b.Helper()
	options := stun.Options{
		Name: name, MTU: uint32(mtu), DNSMode: stun.DNSModeDisabled, EXP_ExternalConfiguration: true, Logger: logger.NOP(),
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
		UDPMapping:    stun.NATMappingAddressAndPortDependent,
		TCPLocalJumbo: config.GetTcpLocalJumbo(),
	})
	cleanup := func() {
		gate.stop()
		cancel()
		if stack != nil {
			_ = stack.Close()
		}
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

type kernelBenchmarkPacketProbe struct {
	maxPacket atomic.Uint32
	stop      func() error
}

// Observe actual host receive packets only during warmup. A configured option
// alone does not prove that the plain-TUN/exact-host jumbo gates were met. The
// socket and its worker are gone before measurement begins.
func benchmarkKernelPacketProbe(b testing.TB, name string, destination netip.Addr) *kernelBenchmarkPacketProbe {
	b.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		b.Fatal(err)
	}
	protocol := int(binary.NativeEndian.Uint16([]byte{0x08, 0x00})) // ETH_P_IP in network byte order
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, protocol)
	if err != nil {
		b.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(protocol), Ifindex: iface.Index}); err != nil {
		_ = unix.Close(fd)
		b.Fatal(err)
	}
	probe := &kernelBenchmarkPacketProbe{}
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		packet := make([]byte, 65535)
		events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		run := func() error {
			for {
				select {
				case <-stop:
					return nil
				default:
				}
				if _, err := unix.Poll(events, 100); err != nil {
					if errors.Is(err, unix.EINTR) {
						continue
					}
					return err
				}
				if events[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
					return fmt.Errorf("packet probe poll event %#x", events[0].Revents)
				}
				if events[0].Revents&unix.POLLIN == 0 {
					continue
				}
				n, _, err := unix.Recvfrom(fd, packet, 0)
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
					continue
				}
				if err != nil {
					return err
				}
				if size := kernelBenchmarkTCPPacketSize(packet[:n], destination); size > probe.maxPacket.Load() {
					probe.maxPacket.Store(size)
				}
			}
		}
		err := run()
		_ = unix.Close(fd)
		done <- err
	}()
	var once sync.Once
	var closeErr error
	probe.stop = func() error {
		once.Do(func() { close(stop); closeErr = <-done })
		return closeErr
	}
	b.Cleanup(func() { _ = probe.stop() })
	return probe
}

func kernelBenchmarkTCPPacketSize(packet []byte, destination netip.Addr) uint32 {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 6 || netip.AddrFrom4([4]byte(packet[16:20])) != destination {
		return 0
	}
	header := int(packet[0]&0xf) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || total > len(packet) || total < header+20 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return 0
	}
	tcpHeader := int(packet[header+12]>>4) * 4
	if tcpHeader < 20 || total <= header+tcpHeader {
		return 0
	}
	return uint32(total)
}

// These wrappers freeze the old controls: an 8KiB SingleReader and sequential
// GoConn.Write, with only download capability exposed in the download control.
// New production capabilities must not silently change those historical paths.
type kernelBenchmarkPlainConn struct {
	net.Conn
	writer buf.Writer
}

func (c *kernelBenchmarkPlainConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return c.writer.WriteMultiBuffer(mb)
}

type kernelBenchmarkDownloadConn struct {
	*kernelBenchmarkPlainConn
	native *tcpConn
	owner  *kernelBenchmarkNative
}

func (c *kernelBenchmarkDownloadConn) ReadFromRaw(ctx context.Context, source net.Conn, progress func(int64)) (int64, bool, error) {
	return c.native.ReadFromRaw(ctx, source, func(n int64) {
		c.owner.rawDownload.Add(n)
		if progress != nil {
			progress(n)
		}
	})
}

type kernelBenchmarkBidirectionalConn struct{ *kernelBenchmarkDownloadConn }

func (c *kernelBenchmarkBidirectionalConn) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	return c.native.WriteToRaw(ctx, target, func(n int64) {
		c.owner.rawUpload.Add(n)
		if progress != nil {
			progress(n)
		}
	})
}

type kernelBenchmarkNative struct {
	*flowHandler
	mode        string
	connections atomic.Uint64
	rawUpload   atomic.Int64
	rawDownload atomic.Int64
}

func (h *kernelBenchmarkNative) uploadEnabled() bool {
	return h.mode == "native_bidirectional_splice" || h.mode == "native_bidirectional_jumbo"
}

func (h *kernelBenchmarkNative) downloadEnabled() bool {
	return h.mode == "native_download_splice" || h.uploadEnabled()
}

func (h *kernelBenchmarkNative) wrap(native *tcpConn) net.Conn {
	var writer buf.Writer = native
	if h.mode == "native_read_write" || h.mode == "native_download_splice" {
		writer = &buf.SequentialWriter{Writer: native.GoConn}
	}
	plain := &kernelBenchmarkPlainConn{Conn: native, writer: writer}
	if !h.downloadEnabled() {
		return plain
	}
	download := &kernelBenchmarkDownloadConn{kernelBenchmarkPlainConn: plain, native: native, owner: h}
	if h.uploadEnabled() {
		return &kernelBenchmarkBidirectionalConn{download}
	}
	return download
}

func (h *kernelBenchmarkNative) assertHandoff(b testing.TB) {
	b.Helper()
	if h.connections.Load() != 1 {
		b.Fatalf("%s adapter received %d connections", h.mode, h.connections.Load())
	}
	if got := h.rawUpload.Load(); (got > 0) != h.uploadEnabled() {
		b.Fatalf("%s native upload bytes=%d (enabled=%v)", h.mode, got, h.uploadEnabled())
	}
	if got := h.rawDownload.Load(); (got > 0) != h.downloadEnabled() {
		b.Fatalf("%s native download bytes=%d (enabled=%v)", h.mode, got, h.downloadEnabled())
	}
}

func (h *kernelBenchmarkNative) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if !h.begin() {
		rejectConnection(conn, onClose)
		return
	}
	err := N.ReportHandshakeSuccess(conn)
	if err == nil {
		native, ok := conn.(*stun.GoConn)
		if !ok {
			err = errors.New("native benchmark did not receive GoConn")
		} else {
			wrapped := &tcpConn{GoConn: native, source: source.TCPAddr(), destination: destination.TCPAddr()}
			h.connections.Add(1)
			h.native.HandleConnectionContext(ctx, h.wrap(wrapped), toDestination(destination, xnet.Network_TCP))
		}
	}
	if err != nil {
		_ = conn.Close()
	}
	if onClose != nil {
		onClose(err)
	}
}

func TestKernelBenchmarkNativeCapabilities(t *testing.T) {
	for _, mode := range kernelBenchmarkProfileModes("vision_tls13") {
		if !strings.HasPrefix(mode, "native_") {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			handler := &kernelBenchmarkNative{mode: mode}
			native := &tcpConn{GoConn: &stun.GoConn{}}
			wrapped := handler.wrap(native)
			_, download := wrapped.(buf.RawReaderFrom)
			_, upload := wrapped.(buf.RawWriterTo)
			if download != handler.downloadEnabled() || upload != handler.uploadEnabled() {
				t.Fatalf("capabilities: download=%v upload=%v", download, upload)
			}
			var plain *kernelBenchmarkPlainConn
			switch wrapped := wrapped.(type) {
			case *kernelBenchmarkPlainConn:
				plain = wrapped
			case *kernelBenchmarkDownloadConn:
				plain = wrapped.kernelBenchmarkPlainConn
			case *kernelBenchmarkBidirectionalConn:
				plain = wrapped.kernelBenchmarkPlainConn
			default:
				t.Fatalf("unexpected adapter %T", wrapped)
			}
			_, sequential := plain.writer.(*buf.SequentialWriter)
			if sequential != (mode == "native_read_write" || mode == "native_download_splice") {
				t.Fatalf("unexpected writer %T", plain.writer)
			}
			if reader, ok := buf.NewReader(wrapped).(*buf.SingleReader); !ok || reader.Reader != wrapped {
				t.Fatalf("control no longer uses ordinary SingleReader: %T", buf.NewReader(wrapped))
			}
		})
	}
}

func TestKernelBenchmarkTCPPacketSize(t *testing.T) {
	destination := netip.MustParseAddr("198.19.1.1")
	packet := make([]byte, 9001)
	packet[0], packet[9], packet[32] = 0x45, 6, 0x50
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[16:20], destination.AsSlice())
	if got := kernelBenchmarkTCPPacketSize(packet, destination); got != uint32(len(packet)) {
		t.Fatalf("packet length=%d", got)
	}
	for _, change := range []func([]byte){
		func(p []byte) { p[9] = 17 },
		func(p []byte) { p[16] ^= 1 },
		func(p []byte) { p[6] = 0x20 },
		func(p []byte) { p[0] = 0x4f },
		func(p []byte) { p[32] = 0xf0; binary.BigEndian.PutUint16(p[2:4], 40) },
		func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 65535) },
	} {
		modified := bytes.Clone(packet)
		change(modified)
		if got := kernelBenchmarkTCPPacketSize(modified, destination); got != 0 {
			t.Fatalf("invalid/non-TCP packet counted as %d bytes", got)
		}
	}
	for length := range 40 {
		if got := kernelBenchmarkTCPPacketSize(packet[:length], destination); got != 0 {
			t.Fatalf("short packet counted as %d bytes", got)
		}
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

// The standalone control uses the same full-Splice owner, with a real direct
// socket to the local application instead of a SOCKS socket or an Xray core.
type kernelBenchmarkDirectDialer struct{ kernelBenchmarkLoopbackDialer }

func (d *kernelBenchmarkDirectDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	destination.Addr = netip.MustParseAddr("127.0.0.1")
	return d.kernelBenchmarkLoopbackDialer.DialContext(ctx, network, destination)
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
