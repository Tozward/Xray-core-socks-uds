package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type rawUplinkTestSource struct {
	*bytes.Reader
	accept bool
	calls  int
}

func (*rawUplinkTestSource) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (*rawUplinkTestSource) Close() error                     { return nil }
func (*rawUplinkTestSource) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*rawUplinkTestSource) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*rawUplinkTestSource) SetDeadline(time.Time) error      { return nil }
func (*rawUplinkTestSource) SetReadDeadline(time.Time) error  { return nil }
func (*rawUplinkTestSource) SetWriteDeadline(time.Time) error { return nil }

func (s *rawUplinkTestSource) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	s.calls++
	if !s.accept {
		return 0, false, nil
	}
	var total int64
	data := make([]byte, 8192)
	for {
		n, readErr := s.Read(data)
		if n > 0 {
			written, err := target.Write(data[:n])
			total += int64(written)
			progress(int64(written))
			if err != nil {
				return total, true, err
			}
		}
		if readErr != nil {
			return total, true, readErr
		}
	}
}

type rawUplinkTestWriter struct {
	buf.Writer
	afterWrite func()
	fail       error
}

func (w *rawUplinkTestWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.fail != nil {
		buf.ReleaseMulti(mb)
		return w.fail
	}
	if err := w.Writer.WriteMultiBuffer(mb); err != nil {
		return err
	}
	w.afterWrite()
	return nil
}

func TestNativeRawUplinkReadinessFallbackAndCounters(t *testing.T) {
	for _, test := range []struct {
		name     string
		accept   bool
		ready    bool
		inbound  int
		chain    bool
		writeErr bool
		wantRaw  bool
	}{
		{"after committed prefix", true, true, 1, false, false, true},
		{"native refuses", false, true, 1, false, false, false},
		{"protocol still framed", true, false, 1, false, false, false},
		{"blocked inbound", true, true, 3, false, false, false},
		{"outbound chain", true, true, 1, true, false, false},
		{"prefix write failed", true, true, 1, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte("native-upload"), 2200)
			source := &rawUplinkTestSource{Reader: bytes.NewReader(payload), accept: test.accept}
			var inboundCount, userCount, outboundCount rawTestCounter
			reader := &buf.TimeoutWrapperReader{
				Reader:  &buf.TimeoutWrapperReader{Reader: buf.NewReader(source), Counter: &inboundCount},
				Counter: &userCount,
			}
			target, consumer := net.Pipe()
			defer target.Close()
			defer consumer.Close()
			_ = target.SetDeadline(time.Now().Add(3 * time.Second))
			_ = consumer.SetDeadline(time.Now().Add(3 * time.Second))
			received := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(consumer); received <- data }()
			counted := &stat.CounterConnection{Connection: target, WriteCounter: &outboundCount}
			committed := false
			failure := errors.New("prefix failed")
			writer := &rawUplinkTestWriter{Writer: buf.NewWriter(counted), afterWrite: func() { committed = true }}
			if test.writeErr {
				writer.fail = failure
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithInbound(ctx, &session.Inbound{CanSpliceCopy: test.inbound, Conn: source})
			outbounds := []*session.Outbound{{}}
			if test.chain {
				outbounds = append(outbounds, &session.Outbound{})
			}
			ctx = session.ContextWithOutbounds(ctx, outbounds)
			timer := signal.CancelAfterInactivity(ctx, cancel, 3*time.Second)
			defer timer.SetTimeout(0)
			err := CopyRawUplink(ctx, reader, writer, timer, func() net.Conn {
				if test.ready && committed {
					return counted
				}
				return nil
			})
			_ = target.Close()
			actual := <-received
			if test.writeErr {
				if !errors.Is(err, failure) || source.calls != 0 || len(actual) != 0 {
					t.Fatalf("failed prefix escaped to raw path: %v calls=%d bytes=%d", err, source.calls, len(actual))
				}
				return
			}
			if err != nil || !bytes.Equal(actual, payload) {
				t.Fatalf("uplink changed data: %v bytes=%d", err, len(actual))
			}
			if test.wantRaw && source.calls != 1 {
				t.Fatalf("raw upload calls=%d", source.calls)
			}
			if !test.wantRaw && test.accept && source.calls != 0 {
				t.Fatalf("unready upload handed off: %d", source.calls)
			}
			for _, counter := range []*rawTestCounter{&inboundCount, &userCount, &outboundCount} {
				if counter.Value() != int64(len(payload)) {
					t.Fatalf("traffic counted %d, want %d", counter.Value(), len(payload))
				}
			}
		})
	}
}

func TestVisionUplinkReadyOnlyAfterSuccessfulFinalPadding(t *testing.T) {
	for _, fails := range []bool{false, true} {
		traffic := NewTrafficState(make([]byte, 16))
		traffic.IsTLS, traffic.EnableXtls, traffic.NumberOfPacketToFilter = true, true, 0
		target := &rawTestTarget{}
		writer := &rawUplinkTestWriter{Writer: target, afterWrite: func() {}}
		if fails {
			writer.fail = errors.New("padding write failed")
		}
		vision := NewVisionWriter(writer, traffic, true, context.Background(), target, nil, nil)
		if vision.RawUplinkTarget() != nil {
			t.Fatal("upload ready before final padding")
		}
		packet := buf.New()
		_, _ = packet.Write([]byte{0x17, 3, 3, 0, 1, 0x41})
		err := vision.WriteMultiBuffer(buf.MultiBuffer{packet})
		if fails {
			if err == nil || vision.RawUplinkTarget() != nil {
				t.Fatal("failed final padding published readiness")
			}
		} else if err != nil || vision.RawUplinkTarget() != target {
			t.Fatalf("successful final padding did not publish readiness: %v", err)
		}
	}
}

func TestNativeRawUplinkLeavesForeignReadinessUntouched(t *testing.T) {
	payload := bytes.Repeat([]byte("ordinary inbound"), 8192)
	source := &rawUplinkTestSource{Reader: bytes.NewReader(payload), accept: true}
	inbound := &session.Inbound{Conn: &rawTestTarget{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
	timer := signal.CancelAfterInactivity(ctx, cancel, time.Second)
	defer timer.SetTimeout(0)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		// A foreign Vision inbound owns this state in its other direction.
		for index := range 10000 {
			inbound.CanSpliceCopy = index%2 + 1
		}
	}()
	var received bytes.Buffer
	err := CopyRawUplink(ctx, buf.NewReader(source), buf.NewWriter(&received), timer, func() net.Conn {
		t.Fatal("foreign inbound queried native readiness")
		return nil
	})
	<-finished
	if err != nil || source.calls != 0 || !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("ordinary inbound changed: %v raw=%d", err, source.calls)
	}
}
