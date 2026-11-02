package proxy

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/finalmask/fragment"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func rawUplinkTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(3 * time.Second))
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	return client.(*net.TCPConn), server
}

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
			if runtime.GOOS != "linux" && runtime.GOOS != "android" && runtime.GOOS != "darwin" {
				test.wantRaw = false
			}
			payload := bytes.Repeat([]byte("native-upload"), 2200)
			source := &rawUplinkTestSource{Reader: bytes.NewReader(payload), accept: test.accept}
			var inboundCount, userCount, outboundCount rawTestCounter
			reader := &buf.TimeoutWrapperReader{
				Reader:  &buf.TimeoutWrapperReader{Reader: buf.NewReader(source), Counter: &inboundCount},
				Counter: &userCount,
			}
			target, consumer := rawUplinkTCPPair(t)
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

type rawUplinkRecordingConn struct {
	net.Conn
	writes []int
}

// Keep the transparent observer traversable by the existing unwrap, so the
// old decision reaches the real TCP socket just as it does without an observer.
func (*rawUplinkRecordingConn) TcpMaskConn()        {}
func (c *rawUplinkRecordingConn) RawConn() net.Conn { return c.Conn }
func (*rawUplinkRecordingConn) Splice() bool        { return true }

func (c *rawUplinkRecordingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return c.Conn.Write(p)
}

type rawUplinkTransformMask struct {
	net.Conn
	writes int
}

func (*rawUplinkTransformMask) TcpMaskConn()        {}
func (c *rawUplinkTransformMask) RawConn() net.Conn { return c.Conn }
func (*rawUplinkTransformMask) Splice() bool        { return true }

func (c *rawUplinkTransformMask) Write(p []byte) (int, error) {
	c.writes++
	transformed := bytes.Clone(p)
	for index := range transformed {
		transformed[index] ^= 0x20
	}
	return c.Conn.Write(transformed)
}

func TestNativeRawUplinkPreservesWriteMasks(t *testing.T) {
	for _, name := range []string{"fragment packets 2-20", "transforming splice-true mask"} {
		t.Run(name, func(t *testing.T) {
			socket, consumer := rawUplinkTCPPair(t)
			payload := bytes.Repeat([]byte("abcdefgh"), 3*buf.Size/8)
			expected := bytes.Clone(payload)
			var target net.Conn
			var verifyWrites func()
			if name == "fragment packets 2-20" {
				recorded := &rawUplinkRecordingConn{Conn: socket}
				config := &fragment.Config{
					PacketsFrom: 2, PacketsTo: 20,
					LengthsMin: []int64{1024}, LengthsMax: []int64{1024},
					DelaysMin: []int64{0}, DelaysMax: []int64{0},
				}
				var err error
				target, err = config.WrapConnClient(recorded, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !IsRAWTransportWithoutSecurity(target) {
					t.Fatal("fragment does not reproduce the raw eligibility")
				}
				raw, _, _ := UnwrapRawConn(target)
				if raw != socket {
					t.Fatalf("fragment observer hid the actual TCP socket: %T", raw)
				}
				verifyWrites = func() {
					if len(recorded.writes) != 1+2*buf.Size/1024 || recorded.writes[0] != buf.Size {
						t.Fatalf("configured packets 2-3 were not fragmented: %v", recorded.writes)
					}
					for _, length := range recorded.writes[1:] {
						if length != 1024 {
							t.Fatalf("fragmented write length: %d", length)
						}
					}
				}
			} else {
				mask := &rawUplinkTransformMask{Conn: socket}
				target = mask
				for index := range expected {
					expected[index] ^= 0x20
				}
				verifyWrites = func() {
					if mask.writes != 3 {
						t.Fatalf("transforming Write called %d times, want 3", mask.writes)
					}
				}
			}
			source := &rawUplinkTestSource{Reader: bytes.NewReader(payload), accept: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: source, CanSpliceCopy: 1})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{}})
			timer := signal.CancelAfterInactivity(ctx, cancel, 3*time.Second)
			defer timer.SetTimeout(0)
			received := make(chan []byte, 1)
			go func() { data, _ := io.ReadAll(consumer); received <- data }()
			err := CopyRawUplink(ctx, buf.NewReader(source), buf.NewWriter(target), timer, func() net.Conn { return target })
			_ = socket.Close()
			actual := <-received
			verifyWrites()
			if err != nil || !bytes.Equal(actual, expected) || source.calls != 0 {
				t.Fatalf("upload bypassed mask: err=%v raw calls=%d bytes=%d", err, source.calls, len(actual))
			}
		})
	}
}

type rawUplinkUnknownConn struct{ net.Conn }

func TestNativeRawUplinkSocketEligibility(t *testing.T) {
	socket, _ := rawUplinkTCPPair(t)
	tlsSocket := &tls.Conn{Conn: gotls.Client(socket, &gotls.Config{})}
	for _, conn := range []net.Conn{
		socket, &stat.CounterConnection{Connection: socket},
		tlsSocket, &stat.CounterConnection{Connection: tlsSocket},
	} {
		if !rawUplinkSocket(conn) {
			t.Fatalf("known protocol-ready socket refused: %T", conn)
		}
		raw, _, _ := UnwrapRawConn(conn)
		if raw != socket {
			t.Fatalf("known ready socket unwrap mismatch: %T", raw)
		}
	}
	masked := &rawUplinkTransformMask{Conn: socket}
	for _, conn := range []net.Conn{
		nil, &rawUplinkUnknownConn{Conn: socket}, masked,
		&stat.CounterConnection{Connection: masked},
		&tls.Conn{Conn: gotls.Client(masked, &gotls.Config{})},
	} {
		if rawUplinkSocket(conn) {
			t.Fatalf("mask or unknown wrapper accepted for upload: %T", conn)
		}
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
