package dispatcher

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

type fragmentedTLSReader struct {
	ctx      context.Context
	declared int
	mode     string
	calls    int
}

func (r *fragmentedTLSReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(time.Second)
}

func (r *fragmentedTLSReader) ReadMultiBufferTimeout(budget time.Duration) (buf.MultiBuffer, error) {
	r.calls++
	if r.calls == 1 {
		return buf.MultiBuffer{buf.FromBytes([]byte{0x16, 3, 1, byte(r.declared >> 8), byte(r.declared)})}, nil
	}
	switch r.mode {
	case "eof":
		return nil, io.EOF
	case "stall", "cancel":
		timer := time.NewTimer(budget)
		defer timer.Stop()
		select {
		case <-r.ctx.Done():
			return nil, r.ctx.Err()
		case <-timer.C:
			return nil, buf.ErrReadTimeout
		}
	}
	if r.calls > 32 {
		return nil, io.EOF
	}
	b := buf.New()
	clear(b.Extend(buf.Size))
	return buf.MultiBuffer{b}, nil
}

func TestFragmentedTLSReadBudgetAndMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		declared int
		mode     string
		maxCalls int
		maxBytes int32
	}{
		{"oversized_65535", 65535, "burst", 2, buf.Size + 5},
		{"oversized_32767", 32767, "burst", 2, buf.Size + 5},
		{"oversized_16385", 16385, "burst", 2, buf.Size + 5},
		{"legal_max_malformed_body", 16384, "burst", 3, 2*buf.Size + 5},
		{"incomplete_eof", 16384, "eof", 2, 5},
		{"incomplete_stall", 16384, "stall", 2, 5},
		{"incomplete_cancel", 16384, "cancel", 2, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance)))
			defer cancel()
			if tc.mode == "cancel" {
				// This reader observes context directly; native TUN cancellation
				// latency is not established by this synthetic propagation check.
				stop := time.AfterFunc(20*time.Millisecond, cancel)
				defer stop.Stop()
			}
			source := &fragmentedTLSReader{ctx: ctx, declared: tc.declared, mode: tc.mode}
			reader := &cachedReader{reader: source}
			defer reader.Interrupt()
			started := time.Now()
			_, err := sniffer(ctx, reader, false, xnet.Network_TCP)
			elapsed := time.Since(started)
			if err == nil {
				t.Fatal("malformed/incomplete TLS unexpectedly recognized")
			}
			if source.calls > tc.maxCalls || reader.cache.Len() > tc.maxBytes {
				t.Fatalf("unbounded input: calls=%d bytes=%d", source.calls, reader.cache.Len())
			}
			if elapsed > time.Second {
				t.Fatalf("read budget failed to terminate: %s", elapsed)
			}
			if tc.mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
			t.Logf("calls=%d retained_bytes=%d elapsed=%s", source.calls, reader.cache.Len(), elapsed)
		})
	}
}

type smallTLSChunkReader struct {
	wire  []byte
	size  int
	calls int
}

func (r *smallTLSChunkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if len(r.wire) == 0 {
		return nil, io.EOF
	}
	size := r.size
	if r.calls == 0 {
		size = 5 // A complete record header identifies TLS before the small chunks.
	}
	size = min(size, len(r.wire))
	buffer := buf.New()
	_, _ = buffer.Write(r.wire[:size])
	r.wire = r.wire[size:]
	r.calls++
	return buf.MultiBuffer{buffer}, nil
}

func TestFragmentedTLSWithSmallReads(t *testing.T) {
	const domain = "fragmented-tls.test"
	client, peer := net.Pipe()
	deadline := time.Now().Add(3 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = peer.SetDeadline(deadline)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(client, &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS13}).Handshake()
	}()
	defer func() { _ = client.Close(); _ = peer.Close(); <-done }()
	header := make([]byte, 5)
	if _, err := io.ReadFull(peer, header); err != nil {
		t.Fatal(err)
	}
	wire := append(header, make([]byte, int(binary.BigEndian.Uint16(header[3:5])))...)
	if _, err := io.ReadFull(peer, wire[5:]); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{32, 128} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			source := &smallTLSChunkReader{wire: wire, size: size}
			reader := &cachedReader{reader: &buf.TimeoutWrapperReader{Reader: source}}
			defer reader.Interrupt()
			ctx := context.WithValue(context.Background(), core.XrayKey(1), new(core.Instance))
			result, err := sniffer(ctx, reader, false, xnet.Network_TCP)
			if err != nil || result == nil || result.Domain() != domain {
				t.Fatalf("domain across %d-byte reads: %v, %v", size, result, err)
			}
			if source.calls <= 2 || reader.cache.Len() != int32(len(wire)) {
				t.Fatalf("fragmented record not preserved: calls=%d bytes=%d", source.calls, reader.cache.Len())
			}
			t.Logf("record_bytes=%d reads=%d", len(wire), source.calls)
		})
	}
}
