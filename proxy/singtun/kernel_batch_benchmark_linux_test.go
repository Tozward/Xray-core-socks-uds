//go:build with_sing_tun && linux && !android

package singtun

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/sys/unix"
)

// BenchmarkKernelNativeBatchFairness measures background bulk download while a
// separate connection exchanges 256-byte requests once per millisecond. Each
// operation is a fixed two-second interval; use -benchtime=1x to avoid calibration
// intervals when comparing dependency overlays. Completed 4MiB downloads alone
// count toward throughput, so partial in-flight transfers do not inflate it.
// The per-flow minimum, Jain index and request tail latency expose starvation
// that aggregate throughput can hide. CPU and network remain loopback fixtures,
// not Android power measurements or external-network capacity measurements.
func BenchmarkKernelNativeBatchFairness(b *testing.B) {
	for _, transport := range []string{"freedom_tls13", "vision_tls13"} {
		b.Run(transport, func(b *testing.B) {
			for _, flows := range []int{1, 4} {
				b.Run(fmt.Sprintf("flows_%d", flows), func(b *testing.B) {
					benchmarkKernelBatchFairness(b, transport, flows)
				})
			}
		})
	}
}

func benchmarkKernelBatchFairness(b *testing.B, transport string, flows int) {
	b.Helper()
	b.StopTimer()
	payload := benchmarkKernelPayload()
	application := func(conn net.Conn) (int64, error) { return kernelBatchApplication(conn, payload) }
	config := memoryCoreConfig(nil)
	var clientTLS *tls.Config
	var port int
	if transport == "vision_tls13" {
		fixture := visionCoreConfig(b, application)
		config, clientTLS, port = fixture.Config, fixture.ClientTLS, int(fixture.Target.Port())
	} else {
		ca, _, _, cert, key := visionCertificates(b)
		port, clientTLS, _ = visionTLSApplication(b, ca, cert, key, application)
	}
	config.App = append([]*serial.TypedMessage{serial.ToTypedMessage(&applog.Config{
		ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None, ErrorLogLevel: clog.Severity_Error,
	})}, config.App...)
	_, name, ip4, ip6 := kernelDeviceMTU(b, 9000)
	_, handler := memoryCore(b, config, session.SniffingRequest{})
	handler.config.TcpLocalJumbo = true
	forwarder := &kernelBenchmarkNative{
		flowHandler: &flowHandler{native: handler.native, mtu: 9000}, mode: "native_bidirectional_jumbo",
	}
	benchmarkKernelStack(b, name, ip4, ip6, 9000, handler.config, handler.ctx, forwarder, forwarder.flowHandler)

	var pathMTU, mss int
	dial := func() net.Conn {
		raw := kernelDial(b, ip4, port)
		control, err := raw.SyscallConn()
		if err != nil {
			b.Fatal(err)
		}
		var queryErr error
		if err = control.Control(func(fd uintptr) {
			pathMTU, queryErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU)
			if queryErr == nil {
				mss, queryErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG)
			}
		}); err != nil {
			b.Fatal(err)
		}
		if queryErr != nil || pathMTU != 9000 || mss < 8940 || mss > 8960 {
			b.Fatalf("batch MTU/MSS mismatch: path=%d mss=%d error=%v", pathMTU, mss, queryErr)
		}
		conn := tls.Client(raw, clientTLS.Clone())
		b.Cleanup(func() { _ = conn.Close() })
		if err := conn.Handshake(); err != nil {
			b.Fatal(err)
		}
		if state := conn.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
			b.Fatal("batch fixture did not establish verified TLS1.3")
		}
		benchmarkSmallRecords(b, conn)
		beforeUpload := forwarder.rawUpload.Load()
		if err := benchmarkWriteAll(conn, []byte{'u'}); err != nil {
			b.Fatal(err)
		}
		if err := benchmarkWriteAll(conn, payload); err != nil {
			b.Fatal(err)
		}
		var ack [1]byte
		if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
			b.Fatalf("batch upload warmup: acknowledgement=%d error=%v", ack[0], err)
		}
		if forwarder.rawUpload.Load() <= beforeUpload {
			b.Fatal("batch connection did not hand off its bulk upload")
		}
		return conn
	}
	transfers := make([]func() error, flows)
	verifies := make([]func() error, flows)
	for index := range flows {
		conn := dial()
		transfers[index], verifies[index], _ = benchmarkKernelTraffic(b, conn, conn, "download")
		if err := transfers[index](); err != nil {
			b.Fatal("bulk warmup: ", err)
		}
		if err := verifies[index](); err != nil {
			b.Fatal(err)
		}
	}
	probe := dial()
	// Exercise the same application download boundary before measuring requests.
	benchmarkKernelJumboWarmup(b, probe)
	if forwarder.connections.Load() != uint64(flows+1) || forwarder.rawDownload.Load() < int64(flows+1)*kernelBenchmarkPayloadSize {
		b.Fatal("batch fixture did not hand off every warmed native download")
	}
	request := append([]byte{'p'}, bytes.Repeat([]byte{0x69}, 256)...)
	response := make([]byte, 256)
	probeOnce := func() error {
		if err := probe.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return err
		}
		if err := benchmarkWriteAll(probe, request); err != nil {
			return err
		}
		if _, err := io.ReadFull(probe, response); err != nil {
			return err
		}
		if !bytes.Equal(response, request[1:]) {
			return fmt.Errorf("batch probe received a different payload")
		}
		return nil
	}
	if err := probeOnce(); err != nil {
		b.Fatal(err)
	}

	counts := make([]atomic.Uint64, flows)
	start, stop := make(chan struct{}), make(chan struct{})
	results := make(chan error, flows)
	var workers sync.WaitGroup
	workers.Add(flows)
	for index := range flows {
		go func() {
			defer workers.Done()
			<-start
			for {
				select {
				case <-stop:
					results <- verifies[index]()
					return
				default:
				}
				if err := transfers[index](); err != nil {
					results <- err
					return
				}
				counts[index].Add(1)
			}
		}()
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	var latencies []time.Duration
	var worstGap time.Duration
	var probeErr error
	b.ResetTimer()
	b.StartTimer()
	started := time.Now()
	previousRequest := started
	close(start)
	deadline := started.Add(time.Duration(b.N) * 2 * time.Second)
	for time.Now().Before(deadline) {
		<-ticker.C
		requestStart := time.Now()
		worstGap = max(worstGap, requestStart.Sub(previousRequest))
		previousRequest = requestStart
		if probeErr = probeOnce(); probeErr != nil {
			break
		}
		latencies = append(latencies, time.Since(requestStart))
	}
	elapsed := time.Since(started)
	b.StopTimer()
	completed := make([]uint64, flows)
	for index := range flows {
		completed[index] = counts[index].Load()
	}
	close(stop)
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			b.Fatal("bulk transfer or payload validation: ", err)
		}
	}
	if probeErr != nil {
		b.Fatal("latency probe: ", probeErr)
	}
	if len(latencies) == 0 {
		b.Fatal("batch interval completed without a latency probe")
	}
	var sum, squares float64
	minimum := completed[0]
	for _, count := range completed {
		if count == 0 {
			b.Fatal("bulk flow made no complete 4MiB progress during the measured interval")
		}
		minimum = min(minimum, count)
		sum += float64(count)
		squares += float64(count) * float64(count)
	}
	b.ReportMetric(sum*kernelBenchmarkPayloadSize/1e6/elapsed.Seconds(), "bulk-MB/s")
	b.ReportMetric(float64(minimum)*kernelBenchmarkPayloadSize/1e6/elapsed.Seconds(), "min-flow-MB/s")
	b.ReportMetric(float64(minimum), "min-completed")
	b.ReportMetric(sum*sum/(float64(flows)*squares), "Jain-index")
	b.ReportMetric(float64(pathMTU), "path-MTU")
	b.ReportMetric(float64(mss), "local-MSS")
	b.ReportMetric(float64(len(latencies)), "probe-count")
	b.ReportMetric(float64(worstGap.Nanoseconds())/1e3, "probe-worst-gap-us")
	slices.Sort(latencies)
	for _, percentile := range []int{50, 95, 99, 100} {
		index := (len(latencies)*percentile+99)/100 - 1
		b.ReportMetric(float64(latencies[max(index, 0)].Nanoseconds())/1e3, fmt.Sprintf("probe-p%d-us", percentile))
	}
}

func kernelBatchApplication(conn net.Conn, payload []byte) (int64, error) {
	var received [256]byte
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
		switch command[0] {
		case 'u':
			valid := true
			for offset := 0; offset < len(payload); {
				length := min(len(received), len(payload)-offset)
				if _, err := io.ReadFull(conn, received[:length]); err != nil {
					return total, err
				}
				valid = valid && bytes.Equal(received[:length], payload[offset:offset+length])
				offset += length
			}
			var ack byte
			if valid {
				ack = 1
			}
			if err := benchmarkWriteAll(conn, []byte{ack}); err != nil {
				return total, err
			}
		case 'd', 'j':
			if err := benchmarkWriteAll(conn, payload); err != nil {
				return total, err
			}
			total += int64(len(payload))
		case 'p':
			if _, err := io.ReadFull(conn, received[:]); err != nil {
				return total, err
			}
			if err := benchmarkWriteAll(conn, received[:]); err != nil {
				return total, err
			}
			total += int64(len(received))
		default:
			return total, fmt.Errorf("unexpected batch command %q", command[0])
		}
	}
}
