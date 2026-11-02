package proxy

import (
	"context"
	"io"
	"net"
	"runtime"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
)

// CopyRawUplink keeps the ordinary copier until the protocol permits raw writes
// and a complete read/write batch has finished. Only native single-outbound TCP
// streams opt in. ready runs in this uploader goroutine, never in the downloader.
func CopyRawUplink(ctx context.Context, reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, ready func() net.Conn) error {
	inbound := session.InboundFromContext(ctx)
	var native bool
	if inbound != nil {
		_, native = inbound.Conn.(buf.RawWriterTo)
	}
	stream, capable := reader.(buf.RawWriterTo)
	// Other inbounds may change their readiness in the downloader. Do not read
	// that state at all unless this is the native TUN's fixed ready marker.
	if !native || !capable || inbound.CanSpliceCopy != 1 || len(session.OutboundsFromContext(ctx)) != 1 ||
		(runtime.GOOS != "linux" && runtime.GOOS != "android" && runtime.GOOS != "darwin") {
		return buf.Copy(reader, writer, buf.UpdateActivity(timer))
	}
	return buf.Copy(&rawUplinkReader{
		Reader: reader, stream: stream, ctx: ctx, timer: timer, inboundTimer: inbound.Timer, ready: ready,
	}, writer, buf.UpdateActivity(timer))
}

type rawUplinkReader struct {
	buf.Reader
	stream       buf.RawWriterTo
	ctx          context.Context
	timer        *signal.ActivityTimer
	inboundTimer *signal.ActivityTimer
	ready        func() net.Conn
	readBatch    bool
}

func (r *rawUplinkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// Starting at a post-write checkpoint also drains the common initial sniff
	// cache. Wrappers still decline if a later timed read remains pending.
	if r.readBatch {
		if target := r.ready(); target != nil {
			raw, _, writeCounter := UnwrapRawConn(target)
			_, handled, err := r.stream.WriteToRaw(r.ctx, raw, func(n int64) {
				if writeCounter != nil {
					writeCounter.Add(n)
				}
				r.timer.Update()
				if r.inboundTimer != nil && r.inboundTimer != r.timer {
					r.inboundTimer.Update()
				}
			})
			if handled {
				if err == nil || errors.Cause(err) == io.EOF {
					return nil, io.EOF
				}
				return nil, err
			}
		}
	}
	buffer, err := r.Reader.ReadMultiBuffer()
	if err == nil && !buffer.IsEmpty() {
		r.readBatch = true
	}
	return buffer, err
}
