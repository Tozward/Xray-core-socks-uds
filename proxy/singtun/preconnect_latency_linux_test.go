//go:build with_sing_tun && linux && !android

package singtun

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
)

// This opt-in causal experiment uses only local, authenticated TLS endpoints.
// A relay delays each outer handshake's first server flight, never later data.
// Warm testpre requests must be backed by five workers already offering fully
// dialed connections; the measured application request is not a pool warmup.
// Timing distributions are evidence, not a hard real-time performance contract.
func TestNativeKernelPreconnectLatencyStudy(t *testing.T) {
	if os.Getenv("XRAY_NATIVE_PRECONNECT_STUDY") != "1" {
		t.Skip("set XRAY_NATIVE_PRECONNECT_STUDY=1 for the isolated latency study")
	}
	requireVisionTestpreDiagnostic(t)
	delay := 150 * time.Millisecond
	if value := os.Getenv("XRAY_NATIVE_PRECONNECT_DELAY_MS"); value != "" {
		ms, err := strconv.Atoi(value)
		if err != nil || ms < 0 || ms > 1000 {
			t.Fatal("invalid diagnostic handshake delay")
		}
		delay = time.Duration(ms) * time.Millisecond
	}
	outer := os.Getenv("XRAY_NATIVE_PRECONNECT_OUTER")
	if outer == "" {
		outer = "tls13"
	}
	if outer != "tls13" && outer != "reality" {
		t.Fatal("unsupported diagnostic outer transport")
	}
	for _, path := range []string{"official_stack", "native_read_write", "native_bidirectional_jumbo", "hev_android_defaults"} {
		for _, testpre := range []uint32{0, 5} {
			for _, hello := range []string{"normal", "large_fragmented"} {
				t.Run(fmt.Sprintf("%s/%s/testpre_%d/%s", outer, path, testpre, hello), func(t *testing.T) {
					preconnectLatencyCase(t, path, hello, outer, testpre, delay, false)
				})
			}
		}
	}
}

// The fallback deliberately rejects traffic: an application response requires
// the sniffed TLS domain to select the allowed outbound, not just byte IO.
func TestNativeKernelLargeClientHelloDomainRoute(t *testing.T) {
	for _, path := range []string{"official_stack", "native_bidirectional_jumbo"} {
		t.Run(path, func(t *testing.T) {
			preconnectLatencyCase(t, path, "large_fragmented", "freedom", 0, 0, true)
		})
	}
}

// Keep the real Vision protocol control separate from adapter race checks:
// stock Vision shares filter state between its two forwarding tasks.
func TestVisionKernelLargeClientHelloDomainRoute(t *testing.T) {
	if os.Getenv("XRAY_NATIVE_VISION_PROTOCOL_TESTS") != "1" {
		t.Skip("opt-in non-race protocol control for stock Vision filter state")
	}
	for _, path := range []string{"official_stack", "native_bidirectional_jumbo"} {
		t.Run(path, func(t *testing.T) {
			preconnectLatencyCase(t, path, "large_fragmented", "tls13", 0, 0, true)
		})
	}
}

func preconnectLatencyCase(t *testing.T, path, hello, outer string, testpre uint32, delay time.Duration, domainRoute bool) {
	t.Helper()
	var fixture *visionFixture
	var err error
	relay := &preconnectRelay{}
	if outer == "freedom" {
		ca, _, _, cert, key := visionCertificates(t)
		port, clientTLS, results := visionTLSApplication(t, ca, cert, key)
		config := memoryCoreConfig(nil)
		config.Outbound = config.Outbound[:1]
		config.Outbound[0].Tag = visionOutboundTag
		fixture = &visionFixture{
			Config: config, ClientTLS: clientTLS, ServerResults: results,
			Target: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.90"), uint16(port)),
		}
	} else {
		if outer == "reality" {
			fixture = realityVisionCoreConfig(t, testpre)
		} else {
			fixture = visionCoreConfig(t)
		}
		outbound := fixture.Config.Outbound[0]
		message, err := outbound.ProxySettings.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		proxyConfig := message.(*vlessout.Config)
		account, err := proxyConfig.Vnext.User.Account.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		account.(*vless.Account).Testpre = testpre
		proxyConfig.Vnext.User.Account = serial.ToTypedMessage(account)
		relay = preconnectDelayRelay(t, int(proxyConfig.Vnext.Port), delay)
		proxyConfig.Vnext.Port = uint32(relay.port)
		outbound.ProxySettings = serial.ToTypedMessage(proxyConfig)
	}
	if domainRoute {
		fixture.Config.Outbound = append([]*core.OutboundHandlerConfig{{
			Tag: "unmatched-domain", ProxySettings: serial.ToTypedMessage(&blackhole.Config{}),
		}}, fixture.Config.Outbound...)
		for index, app := range fixture.Config.App {
			if app.Type == serial.GetMessageType(&router.Config{}) {
				fixture.Config.App[index] = serial.ToTypedMessage(&router.Config{Rule: []*router.RoutingRule{{
					TargetTag: &router.RoutingRule_Tag{Tag: visionOutboundTag},
					Domain: []*geodata.DomainRule{{Value: &geodata.DomainRule_Custom{
						Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: visionInnerName},
					}}},
				}}})
			}
		}
	}
	// Keep the relay/node alive until the stock preconnect workers have exited.
	if testpre != 0 {
		waitVisionTestpreWorkersOnCleanup(t)
	}
	baselineStacks := make([]byte, 1<<20)
	baseline := visionTestpreWorkerIDs(&baselineStacks)
	fixture.Config.App = append([]*serial.TypedMessage{serial.ToTypedMessage(&applog.Config{
		ErrorLogType: applog.LogType_None, AccessLogType: applog.LogType_None,
		ErrorLogLevel: clog.Severity_Error,
	})}, fixture.Config.App...)
	fd, name, ip4, ip6 := kernelDeviceMTU(t, 9000)
	sniff := session.SniffingRequest{
		Enabled: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"tls", "fakedns"},
	}
	var instance *core.Instance
	var forwarder *kernelBenchmarkNative
	if strings.HasPrefix(path, "native_") {
		var handler *Handler
		instance, handler = memoryCore(t, fixture.Config, sniff)
		handler.config.TcpLocalJumbo = true
		forwarder = &kernelBenchmarkNative{
			flowHandler: &flowHandler{native: handler.native, mtu: 9000}, mode: path,
		}
		benchmarkKernelStack(t, name, ip4, ip6, 9000, handler.config, handler.ctx, forwarder, forwarder.flowHandler)
	} else {
		receiver := &proxyman.ReceiverConfig{SniffingSettings: &proxyman.SniffingConfig{
			Enabled: true, RouteOnly: true, DestinationOverride: []string{"tls", "fakedns"},
		}}
		var proxySettings *serial.TypedMessage
		socksPort := 0
		if path == "official_stack" {
			proxySettings = serial.ToTypedMessage(&tun.Config{Name: name, MTU: 9000, UserLevel: 7})
		} else {
			socksPort = visionLoopbackPort(t)
			receiver.Listen = xnet.NewIPOrDomain(xnet.LocalHostIP)
			receiver.PortList = &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(socksPort))}}
			proxySettings = serial.ToTypedMessage(&socks.ServerConfig{AuthType: socks.AuthType_NO_AUTH, UserLevel: 7})
		}
		fixture.Config.Inbound = []*core.InboundHandlerConfig{{
			Tag: integrationTag, ReceiverSettings: serial.ToTypedMessage(receiver), ProxySettings: proxySettings,
		}}
		instance, err = core.New(fixture.Config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = instance.Close() })
		if err = instance.Start(); err != nil {
			t.Fatal(err)
		}
		if path == "hev_android_defaults" {
			benchmarkStartHEV(t, fd, ip4, ip6, 9000, socksPort, false)
		}
	}
	quiet := instance.GetFeature((*applog.Instance)(nil)).(*applog.Instance)
	probe := &preconnectPhaseProbe{}
	clog.RegisterHandler(probe)
	t.Cleanup(func() { clog.RegisterHandler(quiet) })
	for request := 0; request < 4; request++ {
		if request > 0 && testpre > 0 {
			preconnectWaitReady(t, baseline, int(testpre))
		}
		sample := &preconnectSample{
			Path: path, Outer: outer, Hello: hello, Testpre: testpre, Request: request,
			DelayMS: float64(delay) / float64(time.Millisecond), Phases: map[string]float64{}, start: time.Now(),
		}
		if path == "hev_android_defaults" && os.Getenv("XRAY_HEV_PIPELINE_CONTROL") == "1" {
			sample.Path = "hev_pipeline_control"
		}
		probe.active.Store(sample)
		beforeUp, beforeDown := int64(0), int64(0)
		if forwarder != nil {
			beforeUp, beforeDown = forwarder.rawUpload.Load(), forwarder.rawDownload.Load()
		}
		raw := kernelDial(t, ip4, int(fixture.Target.Port()))
		sample.mark("tcp_connected")
		clientTLS := fixture.ClientTLS.Clone()
		if hello == "large_fragmented" {
			for i := range 96 {
				clientTLS.NextProtos = append(clientTLS.NextProtos, fmt.Sprintf("diagnostic-%02d-%s", i, strings.Repeat("a", 120)))
			}
		}
		client := tls.Client(&preconnectHelloConn{TCPConn: raw, sample: sample, fragment: hello == "large_fragmented"}, clientTLS)
		if err = client.Handshake(); err != nil {
			t.Fatal("inner TLS handshake: ", err)
		}
		sample.mark("inner_tls_ready")
		if state := client.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
			t.Fatal("application TLS not verified")
		}
		for index, size := range []int{1, 37, 9} {
			payload := bytes.Repeat([]byte{byte(index + 1)}, size)
			if _, err = client.Write(payload); err != nil {
				t.Fatal(err)
			}
			actual := make([]byte, size)
			if _, err = io.ReadFull(client, actual); err != nil || !bytes.Equal(actual, payload) {
				t.Fatal("first responses before next write/EOF: ", err)
			}
			if index == 0 {
				sample.mark("first_application_response")
			}
		}
		_ = client.Close()
		probe.active.Store(nil)
		if forwarder != nil && path == "native_bidirectional_jumbo" &&
			(forwarder.rawUpload.Load() <= beforeUp || forwarder.rawDownload.Load() <= beforeDown) {
			t.Fatal("latency sample did not exercise both native handoff directions")
		}
		sample.RelayAccepts = relay.accepted.Load()
		sample.mu.Lock()
		encoded, encodeErr := json.Marshal(sample)
		sample.mu.Unlock()
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		t.Logf("PRECONNECT_SAMPLE %s", encoded)
	}
}

type preconnectSample struct {
	Path         string             `json:"path"`
	Outer        string             `json:"outer"`
	Hello        string             `json:"hello"`
	Testpre      uint32             `json:"testpre"`
	Request      int                `json:"request"`
	DelayMS      float64            `json:"delay_ms"`
	Phases       map[string]float64 `json:"phases_ms"`
	RelayAccepts uint32             `json:"relay_accepts"`
	HelloBytes   int                `json:"hello_bytes"`
	start        time.Time
	mu           sync.Mutex
	session      string
}

func (s *preconnectSample) mark(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Phases[name]; !exists {
		s.Phases[name] = float64(time.Since(s.start)) / float64(time.Millisecond)
	}
}

type preconnectPhaseProbe struct {
	active atomic.Pointer[preconnectSample]
}

func (*preconnectPhaseProbe) Severity() clog.Severity { return clog.Severity_Info }

var preconnectLogSession = regexp.MustCompile(`\[([0-9]+)\]`)

func (p *preconnectPhaseProbe) Handle(message clog.Message) {
	sample := p.active.Load()
	if sample == nil {
		return
	}
	general, ok := message.(*clog.GeneralMessage)
	if !ok || general.Severity != clog.Severity_Info {
		return
	}
	text := general.String()
	match := preconnectLogSession.FindStringSubmatch(text)
	if len(match) != 2 {
		return
	}
	sample.mu.Lock()
	defer sample.mu.Unlock()
	phase := ""
	if sample.session == "" && (strings.Contains(text, "proxy/tun: processing from ") || strings.Contains(text, "proxy/socks: TCP Connect request to ")) {
		sample.session = match[1]
		phase = "xray_inbound"
	} else if sample.session == match[1] {
		switch {
		case strings.Contains(text, "app/dispatcher: sniffed domain:"):
			phase = "sniffed"
		case strings.Contains(text, "app/dispatcher: default route for ") || strings.Contains(text, "app/dispatcher: taking detour ["):
			phase = "routed"
		case strings.Contains(text, "proxy/vless/outbound: tunneling request to "):
			phase = "outbound_connection_obtained"
		}
	}
	if phase != "" {
		if _, exists := sample.Phases[phase]; !exists {
			sample.Phases[phase] = float64(time.Since(sample.start)) / float64(time.Millisecond)
		}
	}
}

type preconnectHelloConn struct {
	*net.TCPConn
	sample   *preconnectSample
	fragment bool
	wrote    bool
}

func (c *preconnectHelloConn) Write(b []byte) (int, error) {
	if c.wrote {
		return c.TCPConn.Write(b)
	}
	c.wrote = true
	c.sample.HelloBytes = len(b)
	c.sample.mark("client_hello_write")
	if !c.fragment || len(b) <= 64 {
		return c.TCPConn.Write(b)
	}
	n, err := c.TCPConn.Write(b[:64])
	if err != nil || n != 64 {
		return n, err
	}
	time.Sleep(25 * time.Millisecond)
	rest, err := c.TCPConn.Write(b[64:])
	return n + rest, err
}

type preconnectRelay struct {
	port     int
	accepted atomic.Uint32
}

func preconnectDelayRelay(t testing.TB, nodePort int, delay time.Duration) *preconnectRelay {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relay := &preconnectRelay{port: listener.Addr().(*net.TCPAddr).Port}
	var mu sync.Mutex
	var connections []net.Conn
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			relay.accepted.Add(1)
			mu.Lock()
			connections = append(connections, client)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				server, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", nodePort), time.Second)
				if err != nil {
					return
				}
				defer server.Close()
				mu.Lock()
				connections = append(connections, server)
				mu.Unlock()
				uploaded := make(chan struct{})
				go func() { _, _ = io.Copy(server, client); _ = server.(*net.TCPConn).CloseWrite(); close(uploaded) }()
				buffer := make([]byte, 32<<10)
				n, readErr := server.Read(buffer)
				if n > 0 {
					time.Sleep(delay)
					if _, err = client.Write(buffer[:n]); err == nil && readErr == nil {
						_, _ = io.Copy(client, server)
					}
				}
				_ = client.Close()
				_ = server.Close()
				<-uploaded
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepted
		mu.Lock()
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return relay
}

// Stock workers block sending on the unbuffered channel only after Dial has
// completed outer TLS/REALITY. Observe, without changing, that existing state.
// Reevaluate this diagnostic when upstream changes its pool implementation.
func preconnectWaitReady(t testing.TB, baseline map[string]struct{}, count int) {
	t.Helper()
	stacks := make([]byte, 1<<20)
	deadline := time.Now().Add(4 * time.Second)
	for {
		n := runtime.Stack(stacks, true)
		if n == len(stacks) {
			stacks = make([]byte, len(stacks)*2)
			continue
		}
		ready := 0
		for _, stack := range bytes.Split(stacks[:n], []byte("\n\n")) {
			fields := bytes.Fields(stack)
			if len(fields) < 3 {
				continue
			}
			if _, old := baseline[string(fields[1])]; old {
				continue
			}
			if bytes.Contains(stack, []byte("[chan send")) && bytes.Contains(stack, []byte("github.com/xtls/xray-core/proxy/vless/outbound.(*Handler).Process.func1.1()")) {
				ready++
			}
		}
		if ready == count {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d preconnections ready", ready, count)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
