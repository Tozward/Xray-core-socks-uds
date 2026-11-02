package socks_uds

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type associationDispatcher struct {
	link *transport.Link
	seen chan struct{}
}

func (*associationDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*associationDispatcher) Start() error      { return nil }
func (*associationDispatcher) Close() error      { return nil }
func (d *associationDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	close(d.seen)
	return d.link, nil
}
func (*associationDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	panic("unexpected DispatchLink")
}

type associationWriter struct{ interrupted atomic.Bool }

func (*associationWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}
func (w *associationWriter) Interrupt() { w.interrupted.Store(true) }

type associationReader struct {
	buffer     buf.MultiBuffer
	finalError error
	read       chan struct{}
	stop       chan struct{}
	once       sync.Once
}

func (r *associationReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.buffer != nil {
		mb := r.buffer
		r.buffer = nil
		return mb, r.finalError
	}
	close(r.read)
	<-r.stop
	return nil, io.EOF
}
func (r *associationReader) Interrupt() { r.once.Do(func() { close(r.stop) }) }

func associationFrame(payload []byte) []byte {
	packet := append([]byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 53}, payload...)
	frame := make([]byte, 2, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	return append(frame, packet...)
}

func serveAssociation(t *testing.T, ctx context.Context, dispatcher routing.Dispatcher) (net.Conn, <-chan error) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan error, 1)
	go func() {
		done <- (&Server{policyManager: policy.DefaultManager{}}).Process(ctx, xnet.Network_TCP, server, dispatcher)
	}()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("association handshake: %v %v", method, err)
	}
	if _, err := client.Write([]byte{5, 3, 0, 1, 192, 0, 2, 1, 0, 53}); err != nil {
		t.Fatal(err)
	}
	var reply [5]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 5 || reply[1] != 0 || reply[3] != 5 {
		t.Fatalf("association reply: %v %v", reply, err)
	}
	if _, err := io.CopyN(io.Discard, client, int64(reply[4])+2); err != nil {
		t.Fatal(err)
	}
	return client, done
}

func TestUDPAssociationCancellationClosesLinks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &associationReader{read: make(chan struct{}), stop: make(chan struct{})}
	writer := &associationWriter{}
	dispatcher := &associationDispatcher{link: &transport.Link{Reader: reader, Writer: writer}, seen: make(chan struct{})}
	client, done := serveAssociation(t, ctx, dispatcher)
	if _, err := client.Write(associationFrame([]byte("request"))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.read:
	case <-time.After(3 * time.Second):
		t.Fatal("downlink reader did not start")
	}
	cancel()
	select {
	case <-done:
		if !writer.interrupted.Load() {
			t.Fatal("association returned without interrupting the outbound writer")
		}
		select {
		case <-reader.stop:
		default:
			t.Fatal("association retained its downlink reader")
		}
	case <-time.After(3 * time.Second):
		reader.Interrupt()
		t.Fatal("cancelled association retained a blocked frame read")
	}
}

func TestUDPAssociationDrainsPayloadBeforeEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	payload := buf.New()
	_, _ = payload.Write([]byte("final reply"))
	reader := &associationReader{buffer: buf.MultiBuffer{payload}, finalError: io.EOF, read: make(chan struct{}), stop: make(chan struct{})}
	dispatcher := &associationDispatcher{link: &transport.Link{Reader: reader, Writer: &associationWriter{}}, seen: make(chan struct{})}
	client, done := serveAssociation(t, ctx, dispatcher)
	if _, err := client.Write(associationFrame([]byte("request"))); err != nil {
		t.Fatal(err)
	}
	want := associationFrame([]byte("final reply"))
	reply := make([]byte, len(want))
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal("last payload was dropped before EOF: ", err)
	}
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply framing changed: %x", reply)
	}
	_ = client.Close()
	select {
	case <-done:
		if payload.Len() != 0 {
			t.Fatal("last reply buffer was not released")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("association did not release the final link")
	}
}

func TestUDPAssociationDropsOversizeReplyWithoutBreakingFraming(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A legal maximum UDP payload can exceed the stream's uint16 frame when
	// its SOCKS address contains a long domain. The next packet must survive.
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	header := append([]byte{0, 0, 0, 3, byte(len(domain))}, []byte(domain)...)
	header = append(header, 0, 53)
	frame := func(payload []byte) []byte {
		data := append([]byte{0, 0}, header...)
		binary.BigEndian.PutUint16(data, uint16(len(header)+len(payload)))
		return append(data, payload...)
	}
	oversized := buf.NewWithSize(65507)
	_, _ = oversized.Write(bytes.Repeat([]byte{0x69}, 65507))
	reader := &associationReader{
		buffer: buf.MultiBuffer{oversized, buf.FromBytes([]byte("valid reply"))},
		read:   make(chan struct{}), stop: make(chan struct{}),
	}
	dispatcher := &associationDispatcher{link: &transport.Link{Reader: reader, Writer: &associationWriter{}}, seen: make(chan struct{})}
	client, done := serveAssociation(t, ctx, dispatcher)
	if _, err := client.Write(frame([]byte("request"))); err != nil {
		t.Fatal(err)
	}
	want := frame([]byte("valid reply"))
	reply := make([]byte, len(want))
	if _, err := io.ReadFull(client, reply); err != nil || !bytes.Equal(reply, want) {
		t.Fatalf("oversize reply corrupted the next frame: %x %v", reply, err)
	}
	_ = client.Close()
	select {
	case <-done:
		if oversized.Len() != 0 {
			t.Fatal("oversize reply was not released")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("association retained its oversized reply")
	}
}
