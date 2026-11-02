//go:build with_sing_tun

package singtun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	stun "github.com/sagernet/sing-tun"
	sbuf "github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/dns/fakedns"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	statsfeature "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

const integrationTag = "sing-native-test"

func memoryCoreConfig(rules []*router.RoutingRule) *core.Config {
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&policy.Config{System: &policy.SystemPolicy{
				Stats: &policy.SystemPolicy_Stats{InboundUplink: true, InboundDownlink: true, OutboundUplink: true, OutboundDownlink: true},
			}}),
			serial.ToTypedMessage(&router.Config{Rule: rules}),
			serial.ToTypedMessage(&fakedns.FakeDnsPoolMulti{Pools: []*fakedns.FakeDnsPool{{IpPool: "198.18.0.0/15", LruSize: 64}}}),
		},
	}
	for _, tag := range []string{"default", "first", "second", "fake"} {
		config.Outbound = append(config.Outbound, &core.OutboundHandlerConfig{
			Tag: tag,
			ProxySettings: serial.ToTypedMessage(&freedom.Config{
				DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP)}},
				FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			}),
		})
	}
	return config
}

func memoryCore(t testing.TB, config *core.Config, sniff session.SniffingRequest) (*core.Instance, *Handler) {
	t.Helper()
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	ctx := context.WithValue(context.Background(), core.XrayKey(1), instance)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: integrationTag})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: sniff})
	handler, err := NewHandler(ctx, &Config{Name: "memory0", Mtu: 1500, Address: []string{"10.10.14.1/30", "fc00::1/126"}, UserLevel: 7})
	if err != nil {
		t.Fatal(err)
	}
	return instance, handler
}

func memoryPeer(t *testing.T, handler *Handler) *stun.Go {
	t.Helper()
	var clientDevice, inboundDevice *stun.MemoryTun
	link := func(peer **stun.MemoryTun) func([]*sbuf.Buffer) {
		return func(packets []*sbuf.Buffer) {
			for _, packet := range packets {
				_, _ = (*peer).Write(packet.Bytes())
				packet.Release()
			}
		}
	}
	clientDevice = stun.NewMemoryTun(stun.MemoryTunOptions{MTU: 1500, Outbound: link(&inboundDevice)})
	inboundDevice = stun.NewMemoryTun(stun.MemoryTunOptions{MTU: 1500, Outbound: link(&clientDevice)})
	run, err := handler.startDevice(inboundDevice, handler.options())
	if err != nil {
		t.Fatal(err)
	}
	handler.run = run
	ctx, cancel := context.WithCancel(context.Background())
	client, err := stun.NewGo(stun.StackOptions{Context: ctx, Tun: clientDevice, TunOptions: handler.options(), Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = handler.Close(); _ = client.Close(); _ = clientDevice.Close(); cancel() })
	return client
}

func echoTCP(t testing.TB) int {
	return serveTCP(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
}

func serveTCP(t testing.TB, serve func(net.Conn)) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var active []net.Conn
	accepted := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active = append(active, conn)
			mu.Unlock()
			workers.Add(1)
			go func() { defer workers.Done(); defer conn.Close(); serve(conn) }()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-accepted
		mu.Lock()
		for _, conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func echoUDP(t testing.TB) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		data := make([]byte, 65535)
		for {
			n, source, err := conn.ReadFromUDP(data)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(data[:n], source)
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func assertCounter(t testing.TB, instance *core.Instance, name string, minimum int64) {
	t.Helper()
	manager := instance.GetFeature(statsfeature.ManagerType()).(statsfeature.Manager)
	counter := manager.GetCounter(name)
	if counter == nil {
		t.Fatalf("counter %s was not registered", name)
	}
	// Socket writes become visible to the peer before their callers add traffic
	// statistics. Receiving an echo therefore does not synchronize this counter.
	deadline := time.Now().Add(time.Second)
	value := counter.Value()
	for value < minimum && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		value = counter.Value()
	}
	if value < minimum {
		t.Fatalf("counter %s: %d, want >=%d", name, value, minimum)
	}
}

type deferredUDPTestCounter struct {
	statsfeature.Counter
	entered chan struct{}
	resume  chan struct{}
}

func (c *deferredUDPTestCounter) Add(n int64) int64 {
	close(c.entered)
	<-c.resume
	return c.Counter.Add(n)
}

func TestNativeUDPReplyMayPrecedeOutboundAccounting(t *testing.T) {
	port := echoUDP(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	counter := &deferredUDPTestCounter{Counter: new(stats.Counter), entered: make(chan struct{}), resume: make(chan struct{})}
	var once sync.Once
	resume := func() { once.Do(func() { close(counter.resume) }) }
	defer resume()
	writer := &freedom.PacketWriter{
		PacketConnWrapper: &xnet.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}},
		Counter:           counter,
	}
	payload := []byte("reply-before-accounting")
	written := make(chan error, 1)
	go func() { written <- writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(payload)}) }()
	actual := make([]byte, 100)
	n, _, err := conn.ReadFromUDP(actual)
	if err != nil || !bytes.Equal(actual[:n], payload) {
		t.Fatalf("UDP echo: %q, %v", actual[:n], err)
	}
	select {
	case <-counter.entered:
	case <-time.After(time.Second):
		t.Fatal("packet writer did not reach outbound accounting")
	}
	if value := counter.Value(); value != 0 {
		t.Fatalf("counter advanced before write completion was released: %d", value)
	}
	resume()
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if value := counter.Value(); value != int64(len(payload)) {
		t.Fatalf("outbound accounting lost bytes: %d, want %d", value, len(payload))
	}
}

func TestNativeStackDispatchesTCPUDPAndPreservesCounters(t *testing.T) {
	instance, handler := memoryCore(t, memoryCoreConfig(nil), session.SniffingRequest{})
	client := memoryPeer(t, handler)
	tcpPort, udpPort := echoTCP(t), echoUDP(t)
	for _, pair := range [][2]string{{"10.10.14.1", "192.0.2.10"}, {"fc00::1", "2001:db8::10"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := client.DialTCP(ctx, netip.MustParseAddr(pair[0]), netip.AddrPortFrom(netip.MustParseAddr(pair[1]), uint16(tcpPort)))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("native-core-tcp"), 16384)
		written := make(chan error, 1)
		go func() { _, err := conn.Write(payload); written <- err }()
		actual := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, actual); err != nil {
			t.Fatal(err)
		}
		if err = <-written; err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("TCP payload: %v", err)
		}
		_ = conn.Close()
		udp, err := client.DialUDP(netip.AddrPortFrom(netip.MustParseAddr(pair[0]), 0), netip.AddrPortFrom(netip.MustParseAddr(pair[1]), uint16(udpPort)))
		if err != nil {
			t.Fatal(err)
		}
		_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
		for _, size := range []int{32, 1200, 1452, 1472, 1473, 4096} {
			payload = bytes.Repeat([]byte{byte(size)}, size)
			if _, err = udp.Write(payload); err != nil {
				t.Fatal(err)
			}
			actual = make([]byte, size+1)
			n, err := udp.Read(actual)
			if err != nil || !bytes.Equal(payload, actual[:n]) {
				t.Fatalf("UDP %s %d bytes: %v", pair[1], size, err)
			}
		}
		_ = udp.Close()
	}
	assertCounter(t, instance, "inbound>>>"+integrationTag+">>>traffic>>>uplink", 1)
	assertCounter(t, instance, "inbound>>>"+integrationTag+">>>traffic>>>downlink", 1)
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Start(); err == nil {
		t.Fatal("closed inbound restarted")
	}
}

func TestNativeUDPDestinationsHaveIndependentRoutingDecisions(t *testing.T) {
	first, second := echoUDP(t), echoUDP(t)
	rule := func(port int, tag string) *router.RoutingRule {
		return &router.RoutingRule{
			TargetTag: &router.RoutingRule_Tag{Tag: tag}, InboundTag: []string{integrationTag},
			PortList:       &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(port), To: uint32(port)}}},
			SourcePortList: &xnet.PortList{Range: []*xnet.PortRange{{From: 33333, To: 33333}}},
		}
	}
	instance, handler := memoryCore(t, memoryCoreConfig([]*router.RoutingRule{rule(first, "first"), rule(second, "second")}), session.SniffingRequest{})
	client := memoryPeer(t, handler)
	udp, err := client.ListenUDP(netip.MustParseAddrPort("10.10.14.1:33333"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	for index, port := range []int{first, second, first} {
		payload := []byte("destination-" + strconv.Itoa(index))
		if _, err = udp.WriteToUDPAddrPort(payload, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(port))); err != nil {
			t.Fatal(err)
		}
		actual := make([]byte, 100)
		n, _, err := udp.ReadFromUDPAddrPort(actual)
		if err != nil || !bytes.Equal(actual[:n], payload) {
			t.Fatalf("route response: %v", err)
		}
	}
	assertCounter(t, instance, "outbound>>>first>>>traffic>>>uplink", 1)
	assertCounter(t, instance, "outbound>>>second>>>traffic>>>uplink", 1)
}

func TestNativeTCPPreservesClientAddressForRouting(t *testing.T) {
	rule := &router.RoutingRule{
		TargetTag: &router.RoutingRule_Tag{Tag: "first"}, InboundTag: []string{integrationTag},
		SourceIp: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{Custom: &geodata.CIDRRule{
			Cidr: &geodata.CIDR{Ip: []byte{10, 10, 14, 1}, Prefix: 32},
		}}}},
	}
	instance, handler := memoryCore(t, memoryCoreConfig([]*router.RoutingRule{rule}), session.SniffingRequest{})
	client := memoryPeer(t, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, netip.MustParseAddr("10.10.14.1"), netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(echoTCP(t))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write([]byte("source")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(conn, make([]byte, 6)); err != nil {
		t.Fatal(err)
	}
	assertCounter(t, instance, "outbound>>>first>>>traffic>>>uplink", 6)
}

func TestNativeFakeDNSUsesXraySniffingAndRestoresReplyAddress(t *testing.T) {
	port := echoUDP(t)
	rule := &router.RoutingRule{TargetTag: &router.RoutingRule_Tag{Tag: "fake"}, Domain: []*geodata.DomainRule{
		{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "native.test"}}},
	}}
	instance, handler := memoryCore(t, memoryCoreConfig([]*router.RoutingRule{rule}), session.SniffingRequest{
		Enabled: true, MetadataOnly: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"fakedns"},
	})
	client := memoryPeer(t, handler)
	engine := instance.GetFeature((*dnsfeature.FakeDNSEngine)(nil)).(dnsfeature.FakeDNSEngine)
	addresses := engine.GetFakeIPForDomain("native.test")
	if len(addresses) != 1 {
		t.Fatalf("fake mapping: %v", addresses)
	}
	fakeIP, ok := netip.AddrFromSlice(addresses[0].IP())
	if !ok {
		t.Fatal("invalid fake IP")
	}
	destination := netip.AddrPortFrom(fakeIP.Unmap(), uint16(port))
	udp, err := client.ListenUDP(netip.MustParseAddrPort("10.10.14.1:33334"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = udp.WriteToUDPAddrPort([]byte("fake-dns-payload"), destination); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, 100)
	n, source, err := udp.ReadFromUDPAddrPort(actual)
	if err != nil || string(actual[:n]) != "fake-dns-payload" || source != destination {
		t.Fatalf("FakeDNS reply: source=%v, want=%v, payload=%q, err=%v", source, destination, actual[:n], err)
	}
	assertCounter(t, instance, "outbound>>>fake>>>traffic>>>uplink", 1)
}
