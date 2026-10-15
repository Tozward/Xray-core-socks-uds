package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/buf"
)

func TestVisionBuffersValueAndPointerLayouts(t *testing.T) {
	type valueLayout struct {
		input    bytes.Reader
		rawInput bytes.Buffer
	}
	valueConn := &valueLayout{rawInput: *bytes.NewBufferString("value")}
	valueBuffers, err := NewVisionBuffers(valueConn)
	if err != nil {
		t.Fatal(err)
	}
	if valueBuffers.currentRawInput() != &valueConn.rawInput {
		t.Fatal("value layout did not return the rawInput field")
	}

	type pointerLayout struct {
		input    bytes.Reader
		rawInput *bytes.Buffer
	}
	first := bytes.NewBufferString("first")
	pointerConn := &pointerLayout{rawInput: first}
	pointerBuffers, err := NewVisionBuffers(pointerConn)
	if err != nil {
		t.Fatal(err)
	}
	if pointerBuffers.currentRawInput() != first {
		t.Fatal("pointer layout did not return the rawInput field")
	}
	second := bytes.NewBufferString("second")
	pointerConn.rawInput = second
	if pointerBuffers.currentRawInput() != second {
		t.Fatal("pointer layout did not follow a replaced rawInput buffer")
	}
	pointerConn.rawInput = nil
	if pointerBuffers.currentRawInput() != nil {
		t.Fatal("pointer layout did not handle a released rawInput buffer")
	}
}

func TestVisionBuffersTLSImplementations(t *testing.T) {
	for _, conn := range []any{new(tls.Conn), new(utls.Conn), new(reality.Conn)} {
		if _, err := NewVisionBuffers(conn); err != nil {
			t.Errorf("%T: %v", conn, err)
		}
	}
}

func TestVisionBuffersRejectsUnknownLayout(t *testing.T) {
	type unknownLayout struct {
		input    bytes.Reader
		rawInput []byte
	}
	if _, err := NewVisionBuffers(new(unknownLayout)); err == nil {
		t.Fatal("unknown rawInput layout was accepted")
	}
}

type visionBufferReadFunc func() (buf.MultiBuffer, error)

func (f visionBufferReadFunc) ReadMultiBuffer() (buf.MultiBuffer, error) { return f() }

type visionBufferRawConn struct {
	net.Conn
	reader                *bytes.Reader
	closeNotifySuppressed bool
}

func (c *visionBufferRawConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *visionBufferRawConn) SuppressCloseNotify() { c.closeNotifySuppressed = true }

func TestVisionReaderSwitchDrainsCurrentTLSBuffers(t *testing.T) {
	// These fields border the private TLS buffers so an incorrect pointer/value
	// conversion or an oversized reset also changes a checked sentinel.
	type valueLayout struct {
		before   uint64
		input    bytes.Reader
		rawInput bytes.Buffer
		after    [4]uintptr
	}
	type pointerLayout struct {
		before   uint64
		input    bytes.Reader
		rawInput *bytes.Buffer
		after    [4]uintptr
	}
	const before = uint64(0xfedcba9876543210)
	after := [4]uintptr{1, 1, 0, 7}
	decrypted := "final-decrypted-block/"
	pending := bytes.Repeat([]byte("decrypted-pending/"), 193)
	raw := bytes.Repeat([]byte("raw-record/"), 271)
	tail := "subsequent-direct-data"
	userUUID := []byte("vision-test-uuid")

	for _, layout := range []struct {
		name       string
		pointer    bool
		initialNil bool
		release    bool
	}{
		{name: "value"},
		{name: "pointer-replaced", pointer: true},
		{name: "pointer-released", pointer: true, release: true},
		{name: "pointer-initially-nil", pointer: true, initialNil: true},
	} {
		for _, isUplink := range []bool{true, false} {
			direction := "downlink"
			if isUplink {
				direction = "uplink"
			}
			t.Run(layout.name+"/"+direction, func(t *testing.T) {
				var conn any
				var input *bytes.Reader
				var current *bytes.Buffer
				var duringTLSRead func()
				var checkLayout func()
				if layout.pointer {
					oldPooled := bytes.NewBufferString("buffer-returned-to-pool")
					oldCapacity := oldPooled.Cap()
					c := &pointerLayout{before: before, rawInput: oldPooled, after: after}
					if layout.initialNil {
						c.rawInput = nil
					}
					if !layout.release {
						current = bytes.NewBuffer(raw)
					}
					conn, input = c, &c.input
					duringTLSRead = func() { c.rawInput = current }
					checkLayout = func() {
						t.Helper()
						if c.before != before || c.after != after || c.rawInput != current {
							t.Fatal("releasing TLS buffers changed an adjacent field or the rawInput pointer")
						}
						if oldPooled.String() != "buffer-returned-to-pool" || oldPooled.Cap() != oldCapacity {
							t.Fatal("Vision accessed or reset the old pooled buffer")
						}
					}
				} else {
					c := &valueLayout{before: before, after: after}
					c.rawInput.WriteString("previous-record")
					conn, input, current = c, &c.input, &c.rawInput
					duringTLSRead = func() {
						c.rawInput.Reset()
						c.rawInput.Write(raw)
					}
					checkLayout = func() {
						t.Helper()
						if c.before != before || c.after != after {
							t.Fatal("releasing TLS buffers changed an adjacent field")
						}
					}
				}
				buffers, err := NewVisionBuffers(conn)
				if err != nil {
					t.Fatal(err)
				}
				state := NewTrafficState(userUUID)
				state.NumberOfPacketToFilter = 0
				client, peer := net.Pipe()
				t.Cleanup(func() { client.Close(); peer.Close() })
				rawConn := &visionBufferRawConn{Conn: client, reader: bytes.NewReader([]byte(tail))}
				readCalls := 0
				tlsReader := visionBufferReadFunc(func() (buf.MultiBuffer, error) {
					readCalls++
					// The final TLS Read can replace/release rawInput after the
					// VisionReader has already captured the connection layout.
					duringTLSRead()
					input.Reset(pending)
					frame := append([]byte(nil), userUUID...)
					frame = append(frame, 2, 0, byte(len(decrypted)), 0, 3)
					frame = append(frame, decrypted...)
					frame = append(frame, 0xde, 0xad, 0xbe)
					return buf.MultiBuffer{buf.FromBytes(frame)}, nil
				})
				reader := NewVisionReader(tlsReader, state, isUplink, context.Background(), rawConn, buffers, nil)
				got, err := reader.ReadMultiBuffer()
				if err != nil {
					buf.ReleaseMulti(got)
					t.Fatal(err)
				}
				want := decrypted + string(pending)
				if !layout.release {
					want += string(raw)
				}
				actual := got.String()
				buf.ReleaseMulti(got)
				if actual != want {
					t.Fatalf("switch delivered the wrong pending data or order: got %d bytes, want %d", len(actual), len(want))
				}
				checkLayout()
				if input.Len() != 0 || input.Size() != 0 || (current != nil && (current.Len() != 0 || current.Cap() != 0)) {
					t.Fatal("TLS input was drained but its backing storage was not released")
				}
				if reader.buffers != nil || !rawConn.closeNotifySuppressed {
					t.Fatal("Vision did not finish handing the connection over to direct reading")
				}
				if isUplink && !state.Inbound.UplinkReaderDirectCopy || !isUplink && !state.Outbound.DownlinkReaderDirectCopy {
					t.Fatal("the direct-copy command did not update the selected traffic direction")
				}
				got, err = reader.ReadMultiBuffer()
				actual = got.String()
				buf.ReleaseMulti(got)
				if err != nil || actual != tail || readCalls != 1 {
					t.Fatalf("next read did not use the raw connection exactly once: got %q, error %v, TLS calls %d", actual, err, readCalls)
				}
				got, err = reader.ReadMultiBuffer()
				empty := got.IsEmpty()
				buf.ReleaseMulti(got)
				if err != io.EOF || !empty {
					t.Fatalf("pending bytes were replayed after direct reading: empty %v, error %v", empty, err)
				}
			})
		}
	}
}
