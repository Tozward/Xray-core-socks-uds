package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type rawTestCounter struct{ value atomic.Int64 }

func (c *rawTestCounter) Add(n int64) int64 { return c.value.Add(n) - n }
func (c *rawTestCounter) Value() int64      { return c.value.Load() }
func (c *rawTestCounter) Set(n int64) int64 { return c.value.Swap(n) }

type rawTestTarget struct {
	bytes.Buffer
	accept   bool
	calls    int
	normal   int
	onNormal func()
}

func (*rawTestTarget) Close() error                     { return nil }
func (*rawTestTarget) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*rawTestTarget) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*rawTestTarget) SetDeadline(time.Time) error      { return nil }
func (*rawTestTarget) SetReadDeadline(time.Time) error  { return nil }
func (*rawTestTarget) SetWriteDeadline(time.Time) error { return nil }

func (c *rawTestTarget) ReadFromRaw(ctx context.Context, source net.Conn, progress func(int64)) (int64, bool, error) {
	c.calls++
	if !c.accept {
		return 0, false, nil
	}
	var total int64
	data := make([]byte, 31)
	for {
		n, err := source.Read(data)
		if n > 0 {
			_, _ = c.Buffer.Write(data[:n])
			total += int64(n)
			progress(int64(n))
		}
		if err != nil {
			return total, true, err
		}
	}
}

func (c *rawTestTarget) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, packet := range mb {
		c.normal += int(packet.Len())
		_, _ = c.Buffer.Write(packet.Bytes())
	}
	if c.onNormal != nil {
		c.onNormal()
	}
	return nil
}

func TestNativeRawCopyReadinessFallbackAndCounters(t *testing.T) {
	for _, test := range []struct {
		name       string
		inbound    int
		outbound   int
		accept     bool
		transition bool
		wantCalls  int
	}{
		{"ready", 1, 1, true, false, 1},
		{"unsupported endpoint", 1, 1, false, false, 1},
		{"inbound blocked", 3, 1, true, false, 0},
		{"outbound blocked", 1, 3, true, false, 0},
		{"framed prefix before ready", 2, 2, true, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, producer := net.Pipe()
			defer reader.Close()
			defer producer.Close()
			_ = reader.SetReadDeadline(time.Now().Add(3 * time.Second))
			target := &rawTestTarget{accept: test.accept}
			ib := &session.Inbound{CanSpliceCopy: test.inbound, Conn: target}
			ob := &session.Outbound{CanSpliceCopy: test.outbound}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithInbound(ctx, ib)
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{ob})
			if test.transition {
				target.onNormal = func() { ib.CanSpliceCopy = 1; ob.CanSpliceCopy = 1 }
			}
			var sourceCounter, inboundCounter, userCounter rawTestCounter
			writer := &dispatcher.SizeStatWriter{
				Counter: &userCounter,
				Writer:  &tun.TCPWriter{Counter: &inboundCounter, Writer: target},
			}
			payload := bytes.Repeat([]byte("native-raw-data"), 117)
			go func() {
				if test.transition {
					_, _ = producer.Write(payload[:17])
				}
				remaining := payload
				if test.transition {
					remaining = payload[17:]
				}
				_, _ = producer.Write(remaining)
				_ = producer.Close()
			}()
			timer := signal.CancelAfterInactivity(ctx, cancel, 3*time.Second)
			defer timer.SetTimeout(0)
			err := CopyRawConnIfExist(ctx, &stat.CounterConnection{Connection: reader, ReadCounter: &sourceCounter}, target, writer, timer, nil)
			if err != nil {
				t.Fatal(err)
			}
			if target.calls != test.wantCalls || !bytes.Equal(target.Bytes(), payload) {
				t.Fatalf("handoff calls=%d, want=%d; bytes=%d, want=%d", target.calls, test.wantCalls, target.Len(), len(payload))
			}
			if test.transition && target.normal != 17 {
				t.Fatalf("framed prefix bypassed normal writer: %d", target.normal)
			}
			for name, counter := range map[string]*rawTestCounter{"source": &sourceCounter, "inbound": &inboundCounter, "user": &userCounter} {
				if counter.Value() != int64(len(payload)) {
					t.Fatalf("%s counter=%d, want=%d", name, counter.Value(), len(payload))
				}
			}
		})
	}
}

type canceledRawTarget struct{ *rawTestTarget }

func (c *canceledRawTarget) ReadFromRaw(ctx context.Context, _ net.Conn, _ func(int64)) (int64, bool, error) {
	<-ctx.Done()
	return 0, true, ctx.Err()
}

func TestNativeRawCopyRetainsInactivityCancellation(t *testing.T) {
	reader, producer := net.Pipe()
	defer reader.Close()
	defer producer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := &canceledRawTarget{&rawTestTarget{accept: true}}
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: target, CanSpliceCopy: 1})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{CanSpliceCopy: 1}})
	timer := signal.CancelAfterInactivity(ctx, cancel, 30*time.Millisecond)
	defer timer.SetTimeout(0)
	writer := &tun.TCPWriter{Writer: target}
	err := CopyRawConnIfExist(ctx, reader, target, writer, timer, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inactivity did not cancel raw reader: %v", err)
	}
}
