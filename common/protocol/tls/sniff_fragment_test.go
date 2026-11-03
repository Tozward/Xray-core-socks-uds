package tls_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
	xtls "github.com/xtls/xray-core/common/protocol/tls"
)

func TestFragmentedTLSNeedsMoreData(t *testing.T) {
	wire, err := hex.DecodeString("16030100c8010000c403031aacb2a8feb496045bcaf7c1f42e53246e340c5836719759e94166e243a013b60000201a1ac02bc02fc02cc030cca9cca8cc14cc13c013c014009c009d002f0035000a0100007bbaba0000ff01000100000000160014000011632e732d6d6963726f736f66742e636f6d0017000000230000000d00140012040308040401050308050501080606010201000500050100000000001200000010000e000c02683208687474702f312e31000b00020100000a000a0008aaaa001d00170018aaaa000100")
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < 5; cut++ {
		_, err := xtls.SniffTLS(wire[:cut])
		if !errors.Is(err, common.ErrNoClue) {
			t.Fatalf("short header at %d classified as %v", cut, err)
		}
	}
	for cut := 5; cut < len(wire); cut++ {
		_, err := xtls.SniffTLS(wire[:cut])
		if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
			t.Fatalf("incomplete TLS at %d/%d classified as %v", cut, len(wire), err)
		}
	}
	h, err := xtls.SniffTLS(wire)
	if err != nil || h.Domain() != "c.s-microsoft.com" {
		t.Fatalf("complete TLS: %v %v", h, err)
	}
	for _, invalid := range [][]byte{{0x17, 3, 1, 0, 200}, {0x16, 1, 1, 0, 200}} {
		_, err := xtls.SniffTLS(invalid)
		if err == nil || errors.Is(err, protocol.ErrProtoNeedMoreData) {
			t.Fatal("invalid record treated as incomplete TLS", err)
		}
	}
	for _, declared := range []int{16385, 32767, 65535} {
		header := []byte{0x16, 3, 1, byte(declared >> 8), byte(declared)}
		_, err := xtls.SniffTLS(header)
		if !errors.Is(err, common.ErrNoClue) {
			t.Fatalf("oversized declaration %d changed classification: %v", declared, err)
		}
	}
	_, err = xtls.SniffTLS([]byte{0x16, 3, 1, 0x40, 0})
	if !errors.Is(err, protocol.ErrProtoNeedMoreData) {
		t.Fatalf("maximum plaintext record should await content: %v", err)
	}
}
