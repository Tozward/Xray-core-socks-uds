package conf

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"
)

func TestNativeIntegrationExcludesRetiredSocksUDS(t *testing.T) {
	for _, protocol := range []string{"socks_uds", "SOCKS_UDS", "Socks_Uds"} {
		var config InboundDetourConfig
		if err := json.Unmarshal([]byte(`{"protocol":"`+protocol+`","listen":"127.0.0.1","port":1080}`), &config); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Build(); err == nil || !strings.Contains(err.Error(), "unknown config id") {
			t.Fatalf("retired protocol %q must be rejected: %v", protocol, err)
		}
	}
	if _, err := protoregistry.GlobalTypes.FindMessageByName("xray.proxy.socks_uds.ServerConfig"); !errors.Is(err, protoregistry.NotFound) {
		t.Fatalf("retired protocol must not be registered: %v", err)
	}
}

func TestOfficialSocksUnixListenRemainsAvailable(t *testing.T) {
	var config InboundDetourConfig
	// Build only: no listener is opened. The upstream abstract-socket syntax
	// also avoids depending on a platform's filesystem path representation.
	if err := json.Unmarshal([]byte(`{"protocol":"socks","listen":"@native-scope-check","settings":{"auth":"noauth"}}`), &config); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Build(); err != nil {
		t.Fatalf("official Unix socket configuration changed: %v", err)
	}
}
