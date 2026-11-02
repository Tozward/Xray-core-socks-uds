//go:build with_sing_tun && (linux || darwin)

package singtun

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func nativeUnixFileConn(t *testing.T, fd int) *net.UnixConn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "native-handoff-datagram")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.(*net.UnixConn)
}

func TestNativeRawHandoffDeclinesUnixDatagrams(t *testing.T) {
	for _, connected := range []bool{false, true} {
		name := "unconnected"
		if connected {
			name = "connected"
		}
		for _, upload := range []bool{false, true} {
			direction := "download"
			if upload {
				direction = "upload"
			}
			t.Run(name+"/"+direction, func(t *testing.T) {
				var source, peer *net.UnixConn
				if connected {
					pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
					if err != nil {
						t.Fatal(err)
					}
					peer = nativeUnixFileConn(t, pair[1])
					source = nativeUnixFileConn(t, pair[0])
					if source.RemoteAddr() == nil || source.RemoteAddr().Network() != "unixgram" {
						t.Fatal("connected datagram has no Unix datagram peer")
					}
				} else {
					fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
					if err != nil {
						t.Fatal(err)
					}
					source = nativeUnixFileConn(t, fd)
					if source.RemoteAddr() != nil {
						t.Fatal("unconnected datagram unexpectedly has a peer")
					}
				}
				payload := []byte("queued-datagram")
				if peer != nil {
					if _, err := peer.Write(payload); err != nil {
						t.Fatal(err)
					}
				}
				// Unsupported sockets must decline before touching a native stream.
				endpoint := &tcpConn{}
				handoff := endpoint.ReadFromRaw
				if upload {
					handoff = endpoint.WriteToRaw
				}
				progressCalls := 0
				n, handled, err := handoff(context.Background(), source, func(int64) { progressCalls++ })
				if n != 0 || handled || err != nil || progressCalls != 0 {
					t.Fatalf("datagram handoff: bytes=%d handled=%v err=%v progress=%d", n, handled, err, progressCalls)
				}
				raw, err := source.SyscallConn()
				if err != nil {
					t.Fatalf("declined handoff closed the source: %v", err)
				}
				if err := raw.Control(func(fd uintptr) {
					kind, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
					if err != nil || kind != unix.SOCK_DGRAM {
						t.Errorf("declined handoff changed the source socket: kind=%d err=%v", kind, err)
					}
				}); err != nil {
					t.Fatalf("declined handoff closed the source: %v", err)
				}
				if peer != nil {
					if err := source.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
						t.Fatal(err)
					}
					actual := make([]byte, len(payload)+1)
					n, err := source.Read(actual)
					if err != nil || !bytes.Equal(actual[:n], payload) {
						t.Fatalf("declined handoff consumed the datagram: %q %v", actual[:n], err)
					}
				}
			})
		}
	}
}
