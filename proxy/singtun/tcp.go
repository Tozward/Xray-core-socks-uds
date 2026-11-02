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

// tcpConn permits independent native handoffs once Xray has committed each
// direction's framing. It never interprets a proxy protocol; Xray's existing
// Vision state machine owns readiness, and ordinary IO remains the fallback.
type tcpConn struct {
	*stun.GoConn
	source      net.Addr
	destination net.Addr
}

func (c *tcpConn) LocalAddr() net.Addr  { return c.destination }
func (c *tcpConn) RemoteAddr() net.Addr { return c.source }

func (c *tcpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	var storage [32][]byte
	segments := storage[:0]
	if len(mb) > cap(segments) {
		segments = make([][]byte, 0, len(mb))
	}
	for _, buffer := range mb {
		if !buffer.IsEmpty() {
			segments = append(segments, buffer.Bytes())
		}
	}
	if len(segments) == 0 {
		return nil
	}
	_, err := c.GoConn.WriteVector(segments)
	return err
}

func (c *tcpConn) ReadFromRaw(ctx context.Context, source net.Conn, progress func(int64)) (int64, bool, error) {
	return c.spliceDirection(ctx, source, progress, false)
}

func (c *tcpConn) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	return c.spliceDirection(ctx, target, progress, true)
}

func (c *tcpConn) spliceDirection(ctx context.Context, source net.Conn, progress func(int64), upload bool) (int64, bool, error) {
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
	counters := []N.CountFunc{func(n int64) {
		transferred += n
		if progress != nil {
			progress(n)
		}
	}}
	complete := func(err error) { done <- err }
	var accepted bool
	if upload {
		accepted = c.GoConn.SpliceUpload(peer, stun.UploadSpliceOptions{ReadCounters: counters, OnWriteDone: complete})
	} else {
		accepted = c.GoConn.SpliceDownload(peer, stun.DownloadSpliceOptions{WriteCounters: counters, OnReadDone: complete})
	}
	if !accepted {
		return 0, false, nil
	}
	// Cancellation closes this owned native stream, not the original source
	// socket still used by Xray's independent protocol task. Wait for completion
	// so counter callbacks cannot outlive their owning dispatcher invocation.
	stop := context.AfterFunc(ctx, func() { _ = c.GoConn.Close() })
	defer stop()
	err := <-done
	return transferred, true, err
}
