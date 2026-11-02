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
