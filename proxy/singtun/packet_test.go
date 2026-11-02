//go:build with_sing_tun

package singtun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sbuf "github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

type nativePacketRead struct {
	buffer      *sbuf.Buffer
	destination M.Socksaddr
}

type nativePacketTestConn struct {
	incoming    []nativePacketRead
	readIndex   int
	readOptions N.ReadWaitOptions
	initialized bool
	headroom    int
	onWrite     func(*sbuf.Buffer, M.Socksaddr) error
}

func (c *nativePacketTestConn) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	c.initialized = true
	c.readOptions = options
	return false
}

func (c *nativePacketTestConn) WaitReadPacket() (*sbuf.Buffer, M.Socksaddr, error) {
	if c.readIndex == len(c.incoming) {
		return nil, M.Socksaddr{}, io.EOF
	}
	packet := c.incoming[c.readIndex]
	c.readIndex++
	return packet.buffer, packet.destination, nil
}

func (*nativePacketTestConn) ReadPacket(*sbuf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, errors.New("test connection requires its packet read waiter")
}

func (c *nativePacketTestConn) WritePacket(packet *sbuf.Buffer, destination M.Socksaddr) error {
	defer packet.Release()
	if c.onWrite != nil {
		return c.onWrite(packet, destination)
	}
	return nil
}

func (*nativePacketTestConn) Close() error                     { return nil }
func (*nativePacketTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*nativePacketTestConn) SetDeadline(time.Time) error      { return nil }
func (*nativePacketTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*nativePacketTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *nativePacketTestConn) FrontHeadroom() int             { return c.headroom }

type nativePacketBatchTestConn struct {
	*nativePacketTestConn
	onBatch func([]*sbuf.Buffer, []M.Socksaddr) error
}

func (c *nativePacketBatchTestConn) CreatePacketBatchWriter() (N.PacketBatchWriter, bool) {
	return c, true
}

func (c *nativePacketBatchTestConn) WritePacketBatch(packets []*sbuf.Buffer, destinations []M.Socksaddr) error {
	defer sbuf.ReleaseMulti(packets)
	if c.onBatch != nil {
		return c.onBatch(packets, destinations)
	}
	return nil
}

func packetAddress(value string) M.Socksaddr {
	return M.SocksaddrFromNetIP(netip.MustParseAddrPort(value))
}

func newPacketTestAdapter(t testing.TB, conn N.PacketConn, ipv6 bool) *packetConn {
	t.Helper()
	source, destination := "10.0.0.2:24001", "203.0.113.1:443"
	if ipv6 {
		source, destination = "[fd00::2]:24001", "[2001:db8::1]:443"
	}
	adapter, err := newPacketConn(conn, packetAddress(source), packetAddress(destination), 1500)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func managedNativePacket(t testing.TB, payload []byte) *sbuf.Buffer {
	t.Helper()
	packet := sbuf.NewSize(max(1, len(payload)))
	if _, err := packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	return packet
}

func xrayPacket(t testing.TB, payload []byte) *buf.Buffer {
	t.Helper()
	var packet *buf.Buffer
	if len(payload) <= buf.Size {
		packet = buf.New()
	} else {
		packet = buf.NewWithSize(int32(len(payload)))
	}
	if _, err := packet.Write(payload); err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestPacketReadOwnsPayloadAndDestination(t *testing.T) {
	destination := packetAddress("203.0.113.1:443")
	firstBytes := []byte("first datagram")
	firstNative := sbuf.As(firstBytes)
	largeBytes := bytes.Repeat([]byte{0xa5}, buf.Size+4096)
	largeNative := managedNativePacket(t, largeBytes)
	base := &nativePacketTestConn{incoming: []nativePacketRead{
		{buffer: firstNative, destination: destination},
		{buffer: largeNative, destination: destination},
	}}
	adapter := newPacketTestAdapter(t, base, false)
	if !base.initialized || base.readOptions != (N.ReadWaitOptions{}) {
		t.Fatalf("unexpected read waiter initialization: %+v", base.readOptions)
	}

	first, err := adapter.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(first)
	second, err := adapter.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(second)
	if !bytes.Equal(first[0].Bytes(), firstBytes) || !bytes.Equal(second[0].Bytes(), largeBytes) {
		t.Fatal("packet data changed or large datagram was truncated")
	}
	if largeNative.Cap() != 0 {
		t.Fatal("native receive buffer was retained after conversion")
	}
	firstBytes[0] = 'X'
	if first[0].Bytes()[0] != 'f' {
		t.Fatal("Xray retained borrowed native payload storage")
	}
	if first[0].UDP == second[0].UDP || first[0].UDP == &adapter.destination {
		t.Fatal("packet destination metadata aliases another packet or connection")
	}
	first[0].UDP.Address = xnet.DomainAddress("sniffed.example")
	wantDestination := toDestination(destination, xnet.Network_UDP)
	if *second[0].UDP != wantDestination || adapter.destination != wantDestination {
		t.Fatal("rewriting one packet destination changed another packet or original destination")
	}
	if got := adapter.RemoteAddr().String(); got != "10.0.0.2:24001" {
		t.Fatalf("inbound source address = %q", got)
	}
	if got := adapter.LocalAddr().String(); got != destination.String() {
		t.Fatalf("inbound target address = %q", got)
	}
}

func TestPacketReadConsumesEmptyDatagrams(t *testing.T) {
	destination := packetAddress("203.0.113.1:443")
	empty := managedNativePacket(t, nil)
	data := managedNativePacket(t, []byte("next"))
	base := &nativePacketTestConn{incoming: []nativePacketRead{
		{buffer: empty, destination: destination},
		{buffer: data, destination: destination},
	}}
	adapter := newPacketTestAdapter(t, base, false)
	packets, err := adapter.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(packets)
	if base.readIndex != 2 || string(packets[0].Bytes()) != "next" {
		t.Fatal("empty datagram prevented the next datagram from reaching Xray")
	}
	if empty.Cap() != 0 || data.Cap() != 0 {
		t.Fatal("native buffers were not released")
	}
	if _, err := adapter.ReadMultiBuffer(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after final packet: %v", err)
	}
}

func TestPacketAdapterRequiresReadWaiter(t *testing.T) {
	// Hiding optional methods models an unsupported native packet connection.
	conn := struct{ N.PacketConn }{&nativePacketTestConn{}}
	adapter, err := newPacketConn(conn, packetAddress("10.0.0.2:24001"), packetAddress("203.0.113.1:443"), 1500)
	if err == nil || adapter != nil {
		t.Fatal("connection without packet waiter was accepted")
	}
}

func TestPacketWriteBatchMTUBoundary(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name, headerSize := "IPv4", 28
		if ipv6 {
			name, headerSize = "IPv6", 48
		}
		t.Run(name, func(t *testing.T) {
			base := &nativePacketTestConn{headroom: headerSize + 4}
			native := &nativePacketBatchTestConn{nativePacketTestConn: base}
			adapter := newPacketTestAdapter(t, native, ipv6)
			fit := xrayPacket(t, bytes.Repeat([]byte{0x71}, 1500-headerSize))
			large := xrayPacket(t, bytes.Repeat([]byte{0x9d}, 1501-headerSize))
			var borrowedView, ownedPacket *sbuf.Buffer
			calls := 0
			native.onBatch = func(packets []*sbuf.Buffer, destinations []M.Socksaddr) error {
				calls++
				if len(packets) != 2 || len(destinations) != 2 {
					t.Fatal("datagram batch boundaries changed")
				}
				borrowedView, ownedPacket = packets[0], packets[1]
				if packets[0].Start() != 0 || &packets[0].Bytes()[0] != &fit.Bytes()[0] {
					t.Fatal("MTU-fit datagram did not borrow Xray payload")
				}
				if packets[1].Start() < base.headroom || &packets[1].Bytes()[0] == &large.Bytes()[0] {
					t.Fatal("oversized datagram did not receive owned header space")
				}
				if !bytes.Equal(packets[0].Bytes(), fit.Bytes()) || !bytes.Equal(packets[1].Bytes(), large.Bytes()) {
					t.Fatal("datagram payload changed before synchronous write completed")
				}
				// Match the native batch writer's fragmented-datagram fallback.
				packets[1].ExtendHeader(headerSize)
				if fit.Cap() == 0 || large.Cap() == 0 {
					t.Fatal("Xray released payload before native writer finished")
				}
				return nil
			}
			if err := adapter.WriteMultiBuffer(buf.MultiBuffer{fit, large}); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || fit.Cap() != 0 || large.Cap() != 0 || ownedPacket.Cap() != 0 {
				t.Fatal("write did not consume all owned buffers exactly by return")
			}
			// As() is an unmanaged view; its Release must not return Xray storage
			// to the independent sing allocator. Do not read its released payload.
			if borrowedView.Cap() != 1500-headerSize {
				t.Fatal("borrowed payload view was treated as native-owned storage")
			}
		})
	}
}

func TestPacketWriteFallbackHeadroomAndReplyAddress(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name, headerSize, alternate := "IPv4", 28, "198.51.100.9:5353"
		if ipv6 {
			name, headerSize, alternate = "IPv6", 48, "[2001:db8::9]:5353"
		}
		t.Run(name, func(t *testing.T) {
			base := &nativePacketTestConn{headroom: headerSize + 4}
			adapter := newPacketTestAdapter(t, base, ipv6)
			metadata := []*xnet.Destination{
				nil,
				{Network: xnet.Network_UDP, Port: 443},
				{Network: xnet.Network_UDP, Address: xnet.DomainAddress("sniffed.example"), Port: 443},
			}
			alternateDestination := toDestination(packetAddress(alternate), xnet.Network_UDP)
			metadata = append(metadata, &alternateDestination)
			var originals []*buf.Buffer
			var nativePackets []*sbuf.Buffer
			for index := range metadata {
				payload := bytes.Repeat([]byte{byte(index + 1)}, 10+index)
				packet := xrayPacket(t, payload)
				packet.UDP = metadata[index]
				originals = append(originals, packet)
			}
			calls := 0
			base.onWrite = func(packet *sbuf.Buffer, destination M.Socksaddr) error {
				index := calls
				calls++
				nativePackets = append(nativePackets, packet)
				if packet.Start() < base.headroom || &packet.Bytes()[0] == &originals[index].Bytes()[0] {
					t.Fatal("fallback writer received borrowed data without headroom")
				}
				if !bytes.Equal(packet.Bytes(), originals[index].Bytes()) {
					t.Fatal("fallback writer payload changed")
				}
				want := M.SocksaddrFromNet(adapter.destination.RawNetAddr())
				if index == len(metadata)-1 {
					want = packetAddress(alternate)
				}
				if destination != want {
					t.Fatalf("reply source = %v, want %v", destination, want)
				}
				packet.ExtendHeader(headerSize)
				return nil
			}
			mb := append(buf.MultiBuffer(nil), originals...)
			if err := adapter.WriteMultiBuffer(mb); err != nil {
				t.Fatal(err)
			}
			if calls != len(metadata) {
				t.Fatalf("fallback calls = %d, want %d", calls, len(metadata))
			}
			for index, packet := range originals {
				if packet.Cap() != 0 || nativePackets[index].Cap() != 0 {
					t.Fatal("fallback writer retained owned buffers")
				}
			}
		})
	}
}

func TestPacketWriteFailureReleasesAllBuffers(t *testing.T) {
	wantError := errors.New("native write failed")
	for _, batching := range []bool{false, true} {
		name := "fallback"
		if batching {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			base := &nativePacketTestConn{headroom: 32}
			var conn N.PacketConn = base
			var nativePackets []*sbuf.Buffer
			calls := 0
			if batching {
				native := &nativePacketBatchTestConn{nativePacketTestConn: base}
				native.onBatch = func(packets []*sbuf.Buffer, _ []M.Socksaddr) error {
					calls++
					nativePackets = append(nativePackets, packets...)
					if calls == 2 {
						return wantError
					}
					return nil
				}
				conn = native
			} else {
				base.onWrite = func(packet *sbuf.Buffer, _ M.Socksaddr) error {
					calls++
					nativePackets = append(nativePackets, packet)
					return wantError
				}
			}
			adapter := newPacketTestAdapter(t, conn, false)
			var originals []*buf.Buffer
			for range 35 {
				originals = append(originals, xrayPacket(t, bytes.Repeat([]byte{0x46}, 2000)))
			}
			mb := append(buf.MultiBuffer(nil), originals...)
			if err := adapter.WriteMultiBuffer(mb); !errors.Is(err, wantError) {
				t.Fatalf("write error = %v, want %v", err, wantError)
			}
			for _, packet := range originals {
				if packet.Cap() != 0 {
					t.Fatal("failed write retained an original Xray buffer")
				}
			}
			for _, packet := range nativePackets {
				if packet.Cap() != 0 {
					t.Fatal("failed write retained an owned native buffer")
				}
			}
			if batching && (calls != 2 || len(nativePackets) != 32) {
				t.Fatalf("native failure did not stop later batches: calls=%d packets=%d", calls, len(nativePackets))
			}
		})
	}
}

func TestPacketWriteClearsReusableScratch(t *testing.T) {
	writeError := errors.New("native write failed")
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprintf("failure=%v", failure), func(t *testing.T) {
			native := &nativePacketBatchTestConn{nativePacketTestConn: &nativePacketTestConn{headroom: 32}}
			adapter := newPacketTestAdapter(t, native, false)
			var packetSlots []*sbuf.Buffer
			var destinationSlots []M.Socksaddr
			native.onBatch = func(packets []*sbuf.Buffer, destinations []M.Socksaddr) error {
				packetSlots, destinationSlots = packets, destinations
				if failure {
					return writeError
				}
				return nil
			}
			packet := xrayPacket(t, []byte("borrowed single packet"))
			err := adapter.WriteMultiBuffer(buf.MultiBuffer{packet})
			if failure && !errors.Is(err, writeError) || !failure && err != nil {
				t.Fatalf("write error = %v", err)
			}
			if packet.Cap() != 0 || len(packetSlots) != 1 || packetSlots[0] != nil || destinationSlots[0] != (M.Socksaddr{}) {
				t.Fatal("single-packet write retained payload or address references after return")
			}
		})
	}
}

func TestPacketWriteConcurrentCallers(t *testing.T) {
	native := &nativePacketBatchTestConn{nativePacketTestConn: &nativePacketTestConn{headroom: 32}}
	adapter := newPacketTestAdapter(t, native, false)
	var active atomic.Int32
	native.onBatch = func(packets []*sbuf.Buffer, destinations []M.Socksaddr) error {
		if active.Add(1) != 1 {
			active.Add(-1)
			return errors.New("native packet writer received concurrent calls")
		}
		defer active.Add(-1)
		runtime.Gosched()
		for index, packet := range packets {
			payload := packet.Bytes()
			if len(payload) != 96 {
				return errors.New("concurrent write changed payload length")
			}
			wantDestination := M.SocksaddrFrom(netip.MustParseAddr("198.51.100.9"), 30000+uint16(payload[0]))
			if destinations[index] != wantDestination {
				return fmt.Errorf("concurrent write mixed reply addresses: got %v, want %v", destinations[index], wantDestination)
			}
			for offset, value := range payload {
				if value != payload[offset%3] {
					return errors.New("concurrent write mixed payload bytes")
				}
			}
		}
		return nil
	}
	const workers = 24
	start := make(chan struct{})
	failures := make(chan error, workers)
	var workersDone sync.WaitGroup
	for worker := range workers {
		workersDone.Add(1)
		go func() {
			defer workersDone.Done()
			<-start
			for iteration := range 8 {
				count := 1 + 16*(worker%2)
				packets := make(buf.MultiBuffer, count)
				for index := range packets {
					packet := buf.New()
					_, _ = packet.Write(bytes.Repeat([]byte{byte(worker), byte(iteration), byte(index)}, 32))
					destination := xnet.UDPDestination(xnet.ParseAddress("198.51.100.9"), xnet.Port(30000+worker))
					packet.UDP = &destination
					packets[index] = packet
				}
				originals := append(buf.MultiBuffer(nil), packets...)
				if err := adapter.WriteMultiBuffer(packets); err != nil {
					failures <- err
					return
				}
				for _, packet := range originals {
					if packet.Cap() != 0 {
						failures <- errors.New("concurrent write retained Xray buffer")
						return
					}
				}
			}
		}()
	}
	close(start)
	workersDone.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func BenchmarkPacketWriteBridge(b *testing.B) {
	for _, batching := range []bool{true, false} {
		name := "fallback"
		if batching {
			name = "borrowed_batch"
		}
		for _, batchSize := range []int{1, 16} {
			b.Run(fmt.Sprintf("%s/packets=%d", name, batchSize), func(b *testing.B) {
				base := &nativePacketTestConn{headroom: 32}
				var conn N.PacketConn = base
				if batching {
					conn = &nativePacketBatchTestConn{nativePacketTestConn: base}
				}
				adapter := newPacketTestAdapter(b, conn, false)
				payload := bytes.Repeat([]byte{0x42}, 1200)
				b.SetBytes(int64(len(payload) * batchSize))
				b.ReportAllocs()
				b.ResetTimer()
				b.ReportMetric(float64(reflect.TypeOf(adapter).Elem().Size()), "conn-B")
				for range b.N {
					packets := make(buf.MultiBuffer, batchSize)
					for index := range packets {
						packets[index] = buf.New()
						_, _ = packets[index].Write(payload)
					}
					if err := adapter.WriteMultiBuffer(packets); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

var (
	_ N.PacketConn        = (*nativePacketTestConn)(nil)
	_ N.PacketReadWaiter  = (*nativePacketTestConn)(nil)
	_ N.PacketBatchWriter = (*nativePacketBatchTestConn)(nil)
)
