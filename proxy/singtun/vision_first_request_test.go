//go:build with_sing_tun

package singtun

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/transport/internet"
	transportreality "github.com/xtls/xray-core/transport/internet/reality"
)

// The REALITY decoy and the authenticated inner TLS application are both local.
// This fixture does not contact a public camouflage target or resolve its SNI.
func realityVisionCoreConfig(t testing.TB, testpre uint32) *visionFixture {
	t.Helper()
	ca, outerCert, outerKey, innerCert, innerKey := visionCertificates(t)
	pair, err := tls.X509KeyPair(outerCert, outerKey)
	if err != nil {
		t.Fatal(err)
	}
	decoyPort, _ := visionTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"},
	})
	innerPort, clientTLS, results := visionTLSApplication(t, ca, innerCert, innerKey)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shortID := []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}
	stream := func(config *transportreality.Config) *internet.StreamConfig {
		return &internet.StreamConfig{
			ProtocolName: "tcp", SecurityType: serial.GetMessageType(config),
			SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(config)},
		}
	}
	port := visionLoopbackPort(t)
	nodeConfig := memoryCoreConfig(nil)
	nodeConfig.Inbound = []*core.InboundHandlerConfig{{
		Tag: "reality-vision-node",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			PortList: &xnet.PortList{Range: []*xnet.PortRange{xnet.SinglePortRange(xnet.Port(port))}},
			StreamSettings: stream(&transportreality.Config{
				Dest: fmt.Sprintf("127.0.0.1:%d", decoyPort), Type: "tcp",
				ServerNames: []string{visionOuterName}, PrivateKey: key.Bytes(), ShortIds: [][]byte{shortID},
			}),
		}),
		ProxySettings: serial.ToTypedMessage(&vlessin.Config{
			Decryption: "none", Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{
				Id: visionTestUUID, Flow: vless.XRV,
			})}},
		}),
	}}
	nodeConfig.Outbound = []*core.OutboundHandlerConfig{{
		Tag: "reality-node-loopback", ProxySettings: serial.ToTypedMessage(&freedom.Config{
			DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP)}},
			FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	}}
	node, err := core.New(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	// REALITY's server starts decoy detection asynchronously and otherwise polls
	// it at five-second intervals. Wait for that fixture service to become ready;
	// do not warm the client core, a preconnection or the inner application.
	readyDeadline := time.Now().Add(3 * time.Second)
	for alpn := range 3 {
		cacheKey := fmt.Sprintf("127.0.0.1:%d %s %d", decoyPort, visionOuterName, alpn)
		for {
			value, _ := goreality.GlobalPostHandshakeRecordsLens.Load(cacheKey)
			if _, ready := value.([]int); ready {
				break
			}
			if time.Now().After(readyDeadline) {
				t.Fatal("local REALITY decoy detection did not become ready")
			}
			time.Sleep(time.Millisecond)
		}
	}
	config := memoryCoreConfig(nil)
	config.Outbound = []*core.OutboundHandlerConfig{{
		Tag: visionOutboundTag,
		ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port),
			User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
				Id: visionTestUUID, Flow: vless.XRV, Encryption: "none", Testpre: testpre,
			})},
		}}),
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: stream(&transportreality.Config{
			Fingerprint: "chrome", ServerName: visionOuterName, PublicKey: key.PublicKey().Bytes(),
			ShortId: shortID, SpiderX: "/",
		})}),
	}}
	if testpre != 0 {
		waitVisionTestpreWorkersOnCleanup(t)
	}
	return &visionFixture{
		Config: config, Target: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.90"), uint16(innerPort)),
		ClientTLS: clientTLS, ServerResults: results,
	}
}

// Register after the owned node's cleanup and before creating the client core.
// Cleanup's LIFO order then closes the client first while its node/decoy remain
// available. Stock testpre workers can still be in their 200ms post-send sleep;
// their next successful dial must reach the closed preConns channel to exit.
// Closing the node first instead makes those workers retry failed dials forever.
// These diagnostic fixtures run serially, so new worker IDs belong to this case.
// Reevaluate this stack-based observation when upstream changes testpre ownership.
func waitVisionTestpreWorkersOnCleanup(t testing.TB) {
	t.Helper()
	stacks := make([]byte, 1<<20)
	baseline := visionTestpreWorkerIDs(&stacks)
	t.Logf("testpre worker baseline: %d", len(baseline))
	t.Cleanup(func() {
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		started := time.Now()
		for {
			var remaining []string
			for id := range visionTestpreWorkerIDs(&stacks) {
				if _, preexisting := baseline[id]; !preexisting {
					remaining = append(remaining, id)
				}
			}
			if len(remaining) == 0 {
				t.Logf("testpre workers exited before node shutdown (%s)", time.Since(started))
				return
			}
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatalf("testpre workers survived client shutdown: IDs=%v baseline=%d", remaining, len(baseline))
			}
		}
	})
}

func visionTestpreWorkerIDs(stacks *[]byte) map[string]struct{} {
	for {
		n := runtime.Stack(*stacks, true)
		if n == len(*stacks) {
			*stacks = make([]byte, 2*len(*stacks))
			continue
		}
		workers := make(map[string]struct{})
		for _, stack := range bytes.Split((*stacks)[:n], []byte("\n\n")) {
			if bytes.Contains(stack, []byte("github.com/xtls/xray-core/proxy/vless/outbound.(*Handler).Process.func1.1()")) {
				workers[string(bytes.Fields(stack)[1])] = struct{}{}
			}
		}
		return workers
	}
}

// No bulk transfer or preparatory application records precede the first request.
// Each response must arrive before any second write or client half-close: this
// catches a handoff waiting for another request to flush the first one. Timings
// are diagnostic only; the deadline bounds a protocol stall, not performance.
func visionFirstSmallRequests(t *testing.T, raw net.Conn, config *tls.Config) {
	t.Helper()
	if err := raw.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := tls.Client(raw, config.Clone())
	defer conn.Close()
	started := time.Now()
	if err := conn.Handshake(); err != nil {
		t.Fatal("first inner TLS handshake: ", err)
	}
	t.Logf("inner TLS handshake completed in %s", time.Since(started))
	if state := conn.ConnectionState(); state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatal("first request did not establish verified TLS1.3")
	}
	for index, size := range []int{1, 37, 9} {
		payload := bytes.Repeat([]byte{byte(0x40 + index)}, size)
		started := time.Now()
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("small request %d: %v", index, err)
		}
		actual := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, actual); err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("small response %d before next write/EOF: %x, %v", index, actual, err)
		}
		t.Logf("request %d (%d bytes) completed in %s", index, size, time.Since(started))
	}
}

func TestVisionRealityFirstSmallRequestsOverMemoryTun(t *testing.T) {
	visionRealityFirstSmallRequestsOverMemoryTun(t, 0)
}

// Opt in without -race for protocol checks. A separate -race diagnostic exposes
// stock VLESS testpre's Close/send race; it must not be reported as a clean run.
func TestVisionRealityTestpreFirstSmallRequestsOverMemoryTun(t *testing.T) {
	requireVisionTestpreDiagnostic(t)
	visionRealityFirstSmallRequestsOverMemoryTun(t, 5)
}

func requireVisionTestpreDiagnostic(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAY_NATIVE_TEST_TESTPRE") != "1" {
		t.Skip("opt-in testpre diagnostic: set XRAY_NATIVE_TEST_TESTPRE=1; stock Close/send races under -race")
	}
}

func visionRealityFirstSmallRequestsOverMemoryTun(t *testing.T, testpre uint32) {
	t.Helper()
	fixture := realityVisionCoreConfig(t, testpre)
	_, handler := memoryCore(t, fixture.Config, session.SniffingRequest{
		Enabled: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"tls", "fakedns"},
	})
	client := memoryPeer(t, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for connection := range 3 {
		t.Run(fmt.Sprintf("connection_%d", connection), func(t *testing.T) {
			raw, err := client.DialTCP(ctx, netip.MustParseAddr("10.10.14.1"), fixture.Target)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			visionFirstSmallRequests(t, raw, fixture.ClientTLS)
		})
	}
}
