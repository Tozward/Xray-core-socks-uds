package scenarios

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/log"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	clog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/uuid"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	transtcp "github.com/xtls/xray-core/transport/internet/tcp"
	"golang.org/x/sync/errgroup"
)

func TestVlessXtlsVisionRealityLocal(t *testing.T) {
	payload := bytes.Repeat([]byte("vision-reality-local-echo"), 1<<17)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Errorf("HTTPS echo: %v", err)
		}
	}))
	target.TLS = &stdtls.Config{MinVersion: stdtls.VersionTLS13}
	target.StartTLS()
	defer target.Close()
	_, targetPort, err := stdnet.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(targetPort)
	if err != nil {
		t.Fatal(err)
	}
	dest := net.TCPDestination(net.LocalHostIP, net.Port(portNumber))

	userID := protocol.NewID(uuid.New())
	serverPort := tcp.PickPort()
	privateKey, _ := base64.RawURLEncoding.DecodeString("aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks")
	publicKey, _ := base64.RawURLEncoding.DecodeString("E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM")
	shortIds := make([][]byte, 1)
	shortIds[0] = make([]byte, 8)
	hex.Decode(shortIds[0], []byte("0123456789abcdef"))
	serverConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(serverPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Show:        true,
								Dest:        target.Listener.Addr().String(),
								ServerNames: []string{"example.com"},
								PrivateKey:  privateKey,
								ShortIds:    shortIds,
								Type:        "tcp",
							}),
						},
					},
				}),
				ProxySettings: serial.ToTypedMessage(&inbound.Config{
					Users: []*protocol.User{
						{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	clientPort := tcp.PickPort()
	clientConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&log.Config{
				ErrorLogLevel: clog.Severity_Debug,
				ErrorLogType:  log.LogType_Console,
			}),
		},
		Inbound: []*core.InboundHandlerConfig{
			{
				ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{
					PortList: &net.PortList{Range: []*net.PortRange{net.SinglePortRange(clientPort)}},
					Listen:   net.NewIPOrDomain(net.LocalHostIP),
				}),
				ProxySettings: serial.ToTypedMessage(&dokodemo.Config{
					RewriteAddress:  net.NewIPOrDomain(dest.Address),
					RewritePort:     uint32(dest.Port),
					AllowedNetworks: []net.Network{net.Network_TCP},
				}),
			},
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&outbound.Config{
					Vnext: &protocol.ServerEndpoint{
						Address: net.NewIPOrDomain(net.LocalHostIP),
						Port:    uint32(serverPort),
						User: &protocol.User{
							Account: serial.ToTypedMessage(&vless.Account{
								Id:   userID.String(),
								Flow: vless.XRV,
							}),
						},
					},
				}),
				SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
					StreamSettings: &internet.StreamConfig{
						ProtocolName: "tcp",
						TransportSettings: []*internet.TransportConfig{
							{
								ProtocolName: "tcp",
								Settings:     serial.ToTypedMessage(&transtcp.Config{}),
							},
						},
						SecurityType: serial.GetMessageType(&reality.Config{}),
						SecuritySettings: []*serial.TypedMessage{
							serial.ToTypedMessage(&reality.Config{
								Show:        true,
								Fingerprint: "chrome",
								ServerName:  "example.com",
								PublicKey:   publicKey,
								ShortId:     shortIds[0],
								SpiderX:     "/",
							}),
						},
					},
				}),
			},
		},
	}

	servers, err := InitializeServerConfigs(serverConfig, clientConfig)
	common.Must(err)
	defer CloseAllServers(servers)

	transport := &http.Transport{
		TLSClientConfig: &stdtls.Config{InsecureSkipVerify: true}, // The target is a local test server.
		DialContext: func(ctx context.Context, network, _ string) (stdnet.Conn, error) {
			return (&stdnet.Dialer{}).DialContext(ctx, network, stdnet.JoinHostPort("127.0.0.1", clientPort.String()))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	var errg errgroup.Group
	for range 3 {
		errg.Go(func() error {
			response, err := client.Post("https://example.com/", "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				return err
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil {
				return err
			}
			if response.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
				return fmt.Errorf("HTTPS echo mismatch: status=%d bytes=%d, want=%d", response.StatusCode, len(got), len(payload))
			}
			return nil
		})
	}
	if err := errg.Wait(); err != nil {
		t.Fatal(err)
	}
}
