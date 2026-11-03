//go:build with_sing_tun && linux && !android

package singtun

import (
	"fmt"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
	vlessout "github.com/xtls/xray-core/proxy/vless/outbound"
)

// Unlike MemoryTun, a real Linux TUN can accept socket handoffs. The control
// freezes ordinary IO on the same Sing stack and the same genuine protocol.
// These are first-response/order regressions, not throughput benchmarks.
func TestNativeKernelVisionFirstSmallRequests(t *testing.T) {
	visionKernelFirstSmallRequests(t, 0)
}

func TestNativeKernelVisionTestpreFirstSmallRequests(t *testing.T) {
	requireVisionTestpreDiagnostic(t)
	visionKernelFirstSmallRequests(t, 5)
}

func visionKernelFirstSmallRequests(t *testing.T, testpre uint32) {
	t.Helper()
	for _, outer := range []string{"tls13", "reality"} {
		for _, mode := range []string{"native_read_write", "native_bidirectional_jumbo"} {
			t.Run(fmt.Sprintf("%s/testpre_%d/%s", outer, testpre, mode), func(t *testing.T) {
				var fixture *visionFixture
				if outer == "reality" {
					fixture = realityVisionCoreConfig(t, testpre)
				} else {
					fixture = visionCoreConfig(t)
					outbound := fixture.Config.Outbound[0]
					message, err := outbound.ProxySettings.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					proxyConfig := message.(*vlessout.Config)
					account := proxyConfig.Vnext.User.Account
					message, err = account.GetInstance()
					if err != nil {
						t.Fatal(err)
					}
					message.(*vless.Account).Testpre = testpre
					// TypedMessage stores serialized bytes rather than the mutable
					// message above; update both enclosing messages explicitly.
					proxyConfig.Vnext.User.Account = serial.ToTypedMessage(message)
					outbound.ProxySettings = serial.ToTypedMessage(proxyConfig)
					if testpre != 0 {
						waitVisionTestpreWorkersOnCleanup(t)
					}
				}
				_, name, ip4, ip6 := kernelDeviceMTU(t, 9000)
				_, handler := memoryCore(t, fixture.Config, session.SniffingRequest{
					Enabled: true, RouteOnly: true, OverrideDestinationForProtocol: []string{"tls", "fakedns"},
				})
				handler.config.TcpLocalJumbo = true
				forwarder := &kernelBenchmarkNative{
					flowHandler: &flowHandler{native: handler.native, mtu: 9000}, mode: mode,
				}
				benchmarkKernelStack(t, name, ip4, ip6, 9000, handler.config, handler.ctx, forwarder, forwarder.flowHandler)
				for connection := range 3 {
					t.Run(fmt.Sprintf("connection_%d", connection), func(t *testing.T) {
						beforeUp, beforeDown := forwarder.rawUpload.Load(), forwarder.rawDownload.Load()
						raw := kernelDial(t, ip4, int(fixture.Target.Port()))
						visionFirstSmallRequests(t, raw, fixture.ClientTLS)
						if mode == "native_bidirectional_jumbo" &&
							(forwarder.rawUpload.Load() <= beforeUp || forwarder.rawDownload.Load() <= beforeDown) {
							t.Fatal("small requests did not exercise both native handoff directions")
						}
					})
					if connection == 0 {
						// Let already-established preconnections idle before reuse;
						// this does not issue a preparatory application request.
						time.Sleep(100 * time.Millisecond)
					}
				}
				if forwarder.connections.Load() != 3 {
					t.Fatalf("handled %d streams instead of three", forwarder.connections.Load())
				}
			})
		}
	}
}
