package buf

import (
	"bytes"
	"context"
	"net"
	"testing"
)

type rawForwardCounter int64

func (c *rawForwardCounter) Value() int64 { return int64(*c) }
func (c *rawForwardCounter) Add(n int64) int64 {
	before := *c
	*c += rawForwardCounter(n)
	return int64(before)
}

func (c *rawForwardCounter) Set(n int64) int64 {
	before := *c
	*c = rawForwardCounter(n)
	return int64(before)
}

type rawForwardSource struct {
	*bytes.Reader
	calls int
}

func (s *rawForwardSource) WriteToRaw(context.Context, net.Conn, func(int64)) (int64, bool, error) {
	s.calls++
	return 0, true, nil
}

type rawCountSource struct{ rawForwardSource }

func (s *rawCountSource) WriteToRaw(_ context.Context, _ net.Conn, progress func(int64)) (int64, bool, error) {
	s.calls++
	progress(13)
	return 13, true, nil
}

func TestRawUplinkWrappersDrainPendingReadAndCountOnce(t *testing.T) {
	source := &rawCountSource{rawForwardSource: rawForwardSource{Reader: bytes.NewReader(nil)}}
	var inbound, user rawForwardCounter
	inner := &TimeoutWrapperReader{Reader: &SingleReader{Reader: source}, Counter: &inbound}
	outer := &TimeoutWrapperReader{Reader: inner, Counter: &user}
	inner.done = make(chan struct{})
	inner.mb = MultiBuffer{FromBytes([]byte("cached"))}
	if _, handled, err := outer.WriteToRaw(context.Background(), nil, nil); handled || err != nil || source.calls != 0 {
		t.Fatal("pending read bypassed or consumed during handoff")
	}
	close(inner.done)
	buffer, err := outer.ReadMultiBuffer()
	if err != nil || string(buffer[0].Bytes()) != "cached" {
		t.Fatalf("pending bytes changed: %v", err)
	}
	ReleaseMulti(buffer)
	var progress int64
	n, handled, err := outer.WriteToRaw(context.Background(), nil, func(n int64) { progress += n })
	if err != nil || !handled || n != 13 || progress != 13 || source.calls != 1 {
		t.Fatalf("raw handoff result: %d %v %v progress=%d calls=%d", n, handled, err, progress, source.calls)
	}
	if inbound.Value() != 19 || user.Value() != 19 {
		t.Fatalf("prefix or raw bytes counted twice: %d %d", inbound, user)
	}
}

func TestRawUplinkUnsupportedReaderDoesNotConsume(t *testing.T) {
	source := bytes.NewReader([]byte("untouched"))
	reader := &SingleReader{Reader: source}
	if n, handled, err := reader.WriteToRaw(context.Background(), nil, nil); n != 0 || handled || err != nil || source.Len() != 9 {
		t.Fatal("unsupported reader consumed data")
	}
}
