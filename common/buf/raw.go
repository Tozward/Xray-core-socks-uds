package buf

import (
	"context"
	"net"
)

// RawReaderFrom is an optional native stream handoff after protocol framing
// and cached bytes have been consumed. A false result guarantees no bytes or
// connection ownership were taken. The original source remains caller-owned.
// Progress reports bytes accepted by the target; implementations finish the
// read direction without closing the source's independent write direction.
type RawReaderFrom interface {
	ReadFromRaw(context.Context, net.Conn, func(int64)) (int64, bool, error)
}

// RawWriterTo optionally hands the read direction to a protocol-ready socket.
// The caller must finish writing every previously read buffer first. A false
// result consumes nothing; an accepted call returns at upload EOF or error,
// retaining the target's original descriptor and independent read direction.
type RawWriterTo interface {
	WriteToRaw(context.Context, net.Conn, func(int64)) (int64, bool, error)
}

func (r *SingleReader) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	writer, ok := r.Reader.(RawWriterTo)
	if !ok {
		return 0, false, nil
	}
	return writer.WriteToRaw(ctx, target, progress)
}

func (r *TimeoutWrapperReader) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	// A timed read may have consumed native bytes that have not reached the
	// caller yet. The ordinary reader must drain it before any handoff.
	if r.done != nil {
		return 0, false, nil
	}
	writer, ok := r.Reader.(RawWriterTo)
	if !ok {
		return 0, false, nil
	}
	return writer.WriteToRaw(ctx, target, func(n int64) {
		if r.Counter != nil {
			r.Counter.Add(n)
		}
		if progress != nil {
			progress(n)
		}
	})
}
