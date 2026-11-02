package dispatcher

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/buf"
)

// WriteToRaw preserves sniffed bytes and the statistics wrapper below them.
// Routing has finished before an outbound starts copying; do not keep the cache
// lock across native IO, because cancellation may call Interrupt concurrently.
func (r *cachedReader) WriteToRaw(ctx context.Context, target net.Conn, progress func(int64)) (int64, bool, error) {
	r.Lock()
	buffered := !r.cache.IsEmpty()
	r.Unlock()
	if buffered {
		return 0, false, nil
	}
	writer, ok := r.reader.(buf.RawWriterTo)
	if !ok {
		return 0, false, nil
	}
	return writer.WriteToRaw(ctx, target, progress)
}
