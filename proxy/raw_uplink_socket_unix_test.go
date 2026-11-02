//go:build linux || darwin

package proxy

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func rawUplinkUnixFileConn(t *testing.T, fd int) net.Conn {
	t.Helper()
	file := os.NewFile(uintptr(fd), "raw-uplink-socket")
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestNativeRawUplinkUnixSocketKinds(t *testing.T) {
	for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
		pair, err := unix.Socketpair(unix.AF_UNIX, kind, 0)
		if err != nil {
			t.Fatal(err)
		}
		peer := os.NewFile(uintptr(pair[1]), "raw-uplink-peer")
		t.Cleanup(func() { _ = peer.Close() })
		conn := rawUplinkUnixFileConn(t, pair[0])
		if allowed := rawUplinkSocket(conn); allowed != (kind == unix.SOCK_STREAM) {
			t.Fatalf("socket kind %d allowed=%v", kind, allowed)
		}
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := rawUplinkUnixFileConn(t, fd)
	if conn.RemoteAddr() != nil || rawUplinkSocket(conn) {
		t.Fatal("unconnected datagram must decline upload handoff")
	}
}
