package proxy

import (
	"bytes"
	"fmt"
	"reflect"
	"unsafe"
)

// VisionBuffers exposes the pending TLS input during Vision's switch to raw
// copying. The TLS implementations do not share one rawInput field type:
// REALITY may use *bytes.Buffer while other implementations use bytes.Buffer.
type VisionBuffers struct {
	input       *bytes.Reader
	rawInput    *bytes.Buffer
	rawInputPtr **bytes.Buffer
	owner       any
}

func NewVisionBuffers(conn any) (*VisionBuffers, error) {
	value := reflect.ValueOf(conn)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return nil, fmt.Errorf("Vision requires a pointer to a TLS connection struct, got %T", conn)
	}
	typ := value.Elem().Type()
	inputField, ok := typ.FieldByName("input")
	if !ok || len(inputField.Index) != 1 || inputField.Type != reflect.TypeOf(bytes.Reader{}) {
		return nil, fmt.Errorf("Vision does not support %s.input", typ)
	}
	rawField, ok := typ.FieldByName("rawInput")
	if !ok || len(rawField.Index) != 1 {
		return nil, fmt.Errorf("Vision does not support %s.rawInput", typ)
	}

	base := value.UnsafePointer()
	buffers := &VisionBuffers{
		input: (*bytes.Reader)(unsafe.Add(base, inputField.Offset)),
		owner: conn,
	}
	switch rawField.Type {
	case reflect.TypeOf(bytes.Buffer{}):
		buffers.rawInput = (*bytes.Buffer)(unsafe.Add(base, rawField.Offset))
	case reflect.TypeOf((*bytes.Buffer)(nil)):
		// Keep the address of the field: REALITY can replace this pointer
		// while reading records before Vision switches to raw copying.
		buffers.rawInputPtr = (**bytes.Buffer)(unsafe.Add(base, rawField.Offset))
	default:
		return nil, fmt.Errorf("Vision does not support %s.rawInput of type %s", typ, rawField.Type)
	}
	return buffers, nil
}

func (b *VisionBuffers) currentRawInput() *bytes.Buffer {
	if b.rawInputPtr != nil {
		return *b.rawInputPtr
	}
	return b.rawInput
}
