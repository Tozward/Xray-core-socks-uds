//go:build with_sing_tun

package singtun

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

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
	transporttls "github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

const (
	visionTestUUID    = "b9e84579-86e4-4f46-ae7f-221f4bb6ea17"
	visionOutboundTag = "vision-test"
	visionOuterName   = "outer.vision.test"
	visionInnerName   = "inner.vision.test"
	visionCloseReply  = "vision-inner-tls-close-ack"
)

// visionFixture supplies the same genuine Vision node and inner TLS target to
// MemoryTun tests, privileged kernel-TUN tests and SOCKS comparison benchmarks.
// Config is a client core config; Target is a virtual destination which the
// test node redirects to its loopback-only TLS application server.
type visionFixture struct {
	Config        *core.Config
	Target        netip.AddrPort
	ClientTLS     *tls.Config
	ServerResults <-chan visionServerResult
}

type visionServerResult struct {
	Version uint16
	Bytes   int64
	Err     error
}

func visionCoreConfig(t testing.TB, application ...func(net.Conn) (int64, error)) *visionFixture {
	t.Helper()
	ca, outerCert, outerKey, innerCert, innerKey := visionCertificates(t)
	innerPair, err := tls.X509KeyPair(innerCert, innerKey)
	if err != nil {
		t.Fatal(err)
	}
	innerPort, results := visionTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{innerPair}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	}, application...)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("cannot load test CA")
	}
	port := visionLoopbackPort(t)
	nodeConfig := memoryCoreConfig(nil)
	nodeConfig.Inbound = []*core.InboundHandlerConfig{{
		Tag: "vision-node",
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
			Listen:   xnet.NewIPOrDomain(xnet.LocalHostIP),
			PortList: &xnet.PortList{Range: []*xnet.PortRange{{From: uint32(port), To: uint32(port)}}},
			StreamSettings: visionTLSStream(&transporttls.Config{
				Certificate: []*transporttls.Certificate{{Certificate: outerCert, Key: outerKey, OneTimeLoading: true}},
				MinVersion:  "1.3", MaxVersion: "1.3",
			}),
		}),
		ProxySettings: serial.ToTypedMessage(&vlessin.Config{
			Decryption: "none",
			Users: []*protocol.User{{Account: serial.ToTypedMessage(&vless.Account{
				Id: visionTestUUID, Flow: vless.XRV,
			})}},
		}),
	}}
	nodeConfig.Outbound = []*core.OutboundHandlerConfig{{
		Tag: "vision-node-loopback",
		ProxySettings: serial.ToTypedMessage(&freedom.Config{
			DestinationOverride: &freedom.DestinationOverride{Server: &protocol.ServerEndpoint{Address: xnet.NewIPOrDomain(xnet.LocalHostIP)}},
			FinalRules:          []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
		}),
	}}
	node, err := core.New(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	if err = node.Start(); err != nil {
		t.Fatal(err)
	}
	clientConfig := memoryCoreConfig(nil)
	clientConfig.Outbound = []*core.OutboundHandlerConfig{{
		Tag: visionOutboundTag,
		ProxySettings: serial.ToTypedMessage(&vlessout.Config{Vnext: &protocol.ServerEndpoint{
			Address: xnet.NewIPOrDomain(xnet.LocalHostIP), Port: uint32(port),
			User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
				Id: visionTestUUID, Flow: vless.XRV, Encryption: "none",
			})},
		}}),
		SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{StreamSettings: visionTLSStream(&transporttls.Config{
			ServerName: visionOuterName, MinVersion: "1.3", MaxVersion: "1.3", DisableSystemRoot: true,
			Certificate: []*transporttls.Certificate{{Certificate: ca, Usage: transporttls.Certificate_AUTHORITY_VERIFY, OneTimeLoading: true}},
		})}),
	}}
	return &visionFixture{
		Config: clientConfig, Target: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.90"), uint16(innerPort)),
		ClientTLS:     &tls.Config{RootCAs: roots, ServerName: visionInnerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
		ServerResults: results,
	}
}

func visionTLSStream(config *transporttls.Config) *internet.StreamConfig {
	return &internet.StreamConfig{
		ProtocolName: "tcp", SecurityType: serial.GetMessageType(config),
		SecuritySettings: []*serial.TypedMessage{serial.ToTypedMessage(config)},
	}
}

func visionLoopbackPort(t testing.TB) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func visionCertificates(t testing.TB) (caPEM, outerCert, outerKey, innerCert, innerKey []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sing-tun Vision test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	leaf := func(name string, serial int64) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caPEM...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	outerCert, outerKey = leaf(visionOuterName, 2)
	innerCert, innerKey = leaf(visionInnerName, 3)
	return
}

func visionTLSServer(t testing.TB, config *tls.Config, application ...func(net.Conn) (int64, error)) (int, <-chan visionServerResult) {
	t.Helper()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan visionServerResult, 64)
	var mu sync.Mutex
	var workers sync.WaitGroup
	active := make(map[net.Conn]struct{})
	closing := false
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			active[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer func() { _ = conn.Close(); mu.Lock(); delete(active, conn); mu.Unlock() }()
				_ = conn.SetDeadline(time.Now().Add(time.Minute))
				tlsConn := conn.(*tls.Conn)
				result := visionServerResult{}
				result.Err = tlsConn.Handshake()
				if result.Err == nil {
					result.Version = tlsConn.ConnectionState().Version
					if len(application) != 0 {
						result.Bytes, result.Err = application[0](tlsConn)
					} else {
						result.Bytes, result.Err = io.Copy(tlsConn, tlsConn)
						if result.Err == nil {
							_, result.Err = io.WriteString(tlsConn, visionCloseReply)
						}
					}
					if result.Err == nil {
						result.Err = tlsConn.CloseWrite()
					}
				}
				select {
				case results <- result:
				default:
				}
			}()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closing = true
		_ = listener.Close()
		for conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().(*net.TCPAddr).Port, results
}

func TestVisionTLS13OverMemoryTunPreservesRecordsAndHalfClose(t *testing.T) {
	fixture := visionCoreConfig(t)
	instance, handler := memoryCore(t, fixture.Config, session.SniffingRequest{})
	client := memoryPeer(t, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := client.DialTCP(ctx, netip.MustParseAddr("10.10.14.1"), fixture.Target)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Client(raw, fixture.ClientTLS.Clone())
	defer conn.Close()
	if err = conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		t.Fatalf("inner TLS is not verified TLS1.3: version=%x, chains=%d", state.Version, len(state.VerifiedChains))
	}
	var total int64
	for index, size := range []int{1, 37, 4096, 17 << 10, 256 << 10, 1 << 20} {
		payload := make([]byte, size)
		for position := range payload {
			payload[position] = byte(position*31 + index*17)
		}
		writeDone := make(chan error, 1)
		go func() { _, err := conn.Write(payload); writeDone <- err }()
		actual := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, actual); err != nil {
			t.Fatalf("TLS record payload %d: %v", size, err)
		}
		if err = <-writeDone; err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("ordered TLS payload %d differs: %v", size, err)
		}
		total += int64(len(payload))
	}
	// Closing only the inner TLS upload must still permit the peer's final
	// application response and close_notify to travel through Vision's raw phase.
	if err = conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err = raw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	trailer := make([]byte, len(visionCloseReply))
	if _, err = io.ReadFull(conn, trailer); err != nil || string(trailer) != visionCloseReply {
		t.Fatalf("TLS half-close response: %q, %v", trailer, err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("TLS shutdown produced extra bytes or a record error: n=%d, err=%v", n, err)
	}
	select {
	case result := <-fixture.ServerResults:
		if result.Version != tls.VersionTLS13 || result.Bytes != total || result.Err != nil {
			t.Fatalf("inner server did not receive a clean TLS stream: %+v", result)
		}
	case <-ctx.Done():
		t.Fatal("inner TLS server did not finish")
	}
	assertCounter(t, instance, "inbound>>>"+integrationTag+">>>traffic>>>uplink", total)
	assertCounter(t, instance, "inbound>>>"+integrationTag+">>>traffic>>>downlink", total)
	assertCounter(t, instance, "outbound>>>"+visionOutboundTag+">>>traffic>>>uplink", total)
	assertCounter(t, instance, "outbound>>>"+visionOutboundTag+">>>traffic>>>downlink", total)
}

func TestVisionFixtureRejectsWrongOuterNameAndUser(t *testing.T) {
	fixture := visionCoreConfig(t)
	for _, failure := range []string{"outer-name", "user"} {
		t.Run(failure, func(t *testing.T) {
			config := proto.Clone(fixture.Config).(*core.Config)
			outbound := config.Outbound[0]
			if failure == "outer-name" {
				message, err := outbound.SenderSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				sender := message.(*proxyman.SenderConfig)
				message, err = sender.StreamSettings.SecuritySettings[0].GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				security := message.(*transporttls.Config)
				security.ServerName = "wrong.vision.test"
				sender.StreamSettings.SecuritySettings[0] = serial.ToTypedMessage(security)
				outbound.SenderSettings = serial.ToTypedMessage(sender)
			} else {
				message, err := outbound.ProxySettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				proxyConfig := message.(*vlessout.Config)
				proxyConfig.Vnext.User.Account = serial.ToTypedMessage(&vless.Account{
					Id: "87788c1c-2367-41f4-977c-791e21b1d36b", Flow: vless.XRV, Encryption: "none",
				})
				outbound.ProxySettings = serial.ToTypedMessage(proxyConfig)
			}
			_, handler := memoryCore(t, config, session.SniffingRequest{})
			client := memoryPeer(t, handler)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw, err := client.DialTCP(ctx, netip.MustParseAddr("10.10.14.1"), fixture.Target)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			conn := tls.Client(raw, fixture.ClientTLS.Clone())
			if err = conn.HandshakeContext(ctx); err == nil {
				_ = conn.Close()
				t.Fatalf("%s was accepted", failure)
			}
		})
	}
}
