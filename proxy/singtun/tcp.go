//go:build with_sing_tun

package singtun

import (
	"context"
	"net"
	"syscall"

	stun "github.com/sagernet/sing-tun"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
)

// tcpConn preserves ordinary upload reads while permitting Xray's already-raw
// download to be consumed directly by the native engine. It does not unwrap or
// interpret a proxy protocol; Xray's existing Vision state machine owns that.
type tcpConn struct {
	*stun.GoConn
	source      net.Addr
	destination net.Addr
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.destination }
func (c *tcpConn) RemoteAddr() net.Addr { return c.source }

func (c *tcpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	writer := buf.SequentialWriter{Writer: c.GoConn}
	return writer.WriteMultiBuffer(mb)
}

func (c *tcpConn) ReadFromRaw(ctx context.Context, source net.Conn, progress func(int64)) (int64, bool, error) {
	var peer syscall.Conn
	switch source := source.(type) {
	case *net.TCPConn:
		peer = source
	case *net.UnixConn:
		if source.RemoteAddr().Network() == "unix" {
			peer = source
		}
	}
	if peer == nil {
		return 0, false, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, true, err
	}
	done := make(chan error, 1)
	var transferred int64
	accepted := c.GoConn.SpliceDownload(peer, stun.DownloadSpliceOptions{
		WriteCounters: []N.CountFunc{func(n int64) {
			transferred += n
			if progress != nil {
				progress(n)
			}
		}},
		OnReadDone: func(err error) { done <- err },
	})
	if !accepted {
		return 0, false, nil
	}
	// Cancellation closes this owned native stream, not the original source
	// socket still used by Xray's independent upload task. Wait for completion
	// so counter callbacks cannot outlive their owning dispatcher invocation.
	stop := context.AfterFunc(ctx, func() { _ = c.GoConn.Close() })
	defer stop()
	err := <-done
	return transferred, true, err
}
