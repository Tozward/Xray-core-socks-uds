package proxy

import (
	"bytes"
	"crypto/tls"
	"testing"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
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
