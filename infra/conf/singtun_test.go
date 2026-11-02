package conf

import (
	"strings"
	"testing"

	"github.com/xtls/xray-core/proxy/singtun"
)

func TestSingTunConfigurationAndPortlessInbound(t *testing.T) {
	config, err := (&SingTunConfig{Address: []string{"10.10.14.1/30", "fc00::1/126"}, UserLevel: 7}).Build()
	if !singtun.Enabled {
		if err == nil || !strings.Contains(err.Error(), "with_sing_tun") {
			t.Fatalf("missing optional build should fail explicitly: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	native := config.(*singtun.Config)
	if native.Mtu != 1500 || native.Name == "" || native.UserLevel != 7 || len(native.Address) != 2 {
		t.Fatalf("configuration lost fields: %v", native)
	}
	if native.TcpLocalJumbo {
		t.Fatal("local TCP aggregation must remain opt-in")
	}
	jumbo, err := (&SingTunConfig{Name: "native-test", MTU: 9000, Address: []string{"10.10.14.1/30"}, TCPLocalJumbo: true}).Build()
	if err != nil || !jumbo.(*singtun.Config).TcpLocalJumbo {
		t.Fatalf("explicit local aggregation was lost: %v", err)
	}
	if _, err := (&InboundDetourConfig{Protocol: "sing-tun", Tag: "native-test"}).Build(); err != nil {
		t.Fatalf("native inbound incorrectly requires a port: %v", err)
	}
	for _, bad := range []*SingTunConfig{{MTU: 575}, {MTU: 65536}, {Address: []string{"bad"}}, {MTU: 1200, Address: []string{"fc00::1/126"}}} {
		if _, err := bad.Build(); err == nil {
			t.Fatalf("invalid config accepted: %+v", bad)
		}
	}
}
