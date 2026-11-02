package dispatcher

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type rawCachedTestReader struct{ calls int }

func (*rawCachedTestReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }
func (*rawCachedTestReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return nil, nil
}

func (r *rawCachedTestReader) WriteToRaw(context.Context, net.Conn, func(int64)) (int64, bool, error) {
	r.calls++
	return 0, true, nil
}

func TestRawUplinkCannotBypassSniffedPrefix(t *testing.T) {
	source := &rawCachedTestReader{}
	reader := &cachedReader{reader: source, cache: buf.MultiBuffer{buf.FromBytes([]byte("sniffed prefix"))}}
	if _, accepted, err := reader.WriteToRaw(context.Background(), nil, nil); accepted || err != nil || source.calls != 0 {
		t.Fatal("native upload bypassed sniff cache")
	}
	data, err := reader.ReadMultiBuffer()
	if err != nil || string(data[0].Bytes()) != "sniffed prefix" {
		t.Fatalf("sniffed prefix lost: %v", err)
	}
	buf.ReleaseMulti(data)
	if _, accepted, err := reader.WriteToRaw(context.Background(), nil, nil); !accepted || err != nil || source.calls != 1 {
		t.Fatal("drained sniff cache did not forward handoff")
	}
}
