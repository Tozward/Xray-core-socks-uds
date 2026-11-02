package dispatcher

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) ReadFromRaw(ctx context.Context, source net.Conn, progress func(int64)) (int64, bool, error) {
	reader, ok := w.Writer.(buf.RawReaderFrom)
	if !ok {
		return 0, false, nil
	}
	return reader.ReadFromRaw(ctx, source, func(n int64) {
		w.Counter.Add(n)
		if progress != nil {
			progress(n)
		}
	})
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
