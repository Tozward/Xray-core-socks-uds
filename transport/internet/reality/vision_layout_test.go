package reality

import (
	"bytes"
	"reflect"
	"testing"

	goreality "github.com/xtls/reality"
)

// Vision reads these unexported fields through reflect offsets and unsafe.
// Check the dependency's layout before a REALITY update reaches production.
func TestVisionConnBufferLayout(t *testing.T) {
	connType := reflect.TypeOf(goreality.Conn{})
	for name, want := range map[string]reflect.Type{
		"input":    reflect.TypeOf(bytes.Reader{}),
		"rawInput": reflect.TypeOf((*bytes.Buffer)(nil)),
	} {
		field, ok := connType.FieldByName(name)
		if !ok {
			t.Fatalf("REALITY Conn.%s is missing; Vision's unsafe access needs review", name)
		}
		if field.Type != want {
			t.Fatalf("REALITY Conn.%s has type %v, want %v; Vision's unsafe access needs review", name, field.Type, want)
		}
	}
}
