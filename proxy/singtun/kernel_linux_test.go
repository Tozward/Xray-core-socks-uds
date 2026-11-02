//go:build with_sing_tun && linux && !android

package singtun

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"golang.org/x/sys/unix"
)

var kernelTestSequence atomic.Uint32

// Only a directly connected test subnet is installed. The runner's default
// route, DNS and physical interfaces are never changed. Run on a disposable CI
// machine, with XRAY_REQUIRE_NATIVE_TUN_TESTS=1 to forbid privileged-test skips.
func kernelDevice(t testing.TB) (int, string, netip.Addr, netip.Addr) {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("XRAY_REQUIRE_NATIVE_TUN_TESTS") == "1" {
			t.Fatal("native TUN tests require CAP_NET_ADMIN")
		}
		t.Skip("native TUN tests require a disposable privileged Linux runner")
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	index := kernelTestSequence.Add(1)
	if index > 200 {
		t.Fatal("test address range exhausted")
	}
	ifr, err := unix.NewIfreq(fmt.Sprintf("xn%d_%d", os.Getpid(), index))
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatal(err)
	}
	link, err := netlink.LinkByName(ifr.Name())
	if err != nil {
		t.Fatal(err)
	}
	ip4 := netip.AddrFrom4([4]byte{198, 19, byte(index), 1})
	ip6 := netip.MustParseAddr(fmt.Sprintf("fd78:7261:%x::1", index))
	for _, prefix := range []netip.Prefix{netip.PrefixFrom(ip4, 30), netip.PrefixFrom(ip6, 126)} {
		addr, err := netlink.ParseAddr(prefix.String())
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags = unix.IFA_F_NODAD
		if err = netlink.AddrAdd(link, addr); err != nil {
			t.Fatal(err)
		}
	}
	if err = netlink.LinkSetMTU(link, 1500); err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(platform.TunFdKey, strconv.Itoa(fd))
	return fd, ifr.Name(), ip4, ip6
}

func kernelCore(t testing.TB, config *core.Config, name string, ip4, ip6 netip.Addr) *core.Instance {
	t.Helper()
	config.Inbound = []*core.InboundHandlerConfig{{
		Tag:              integrationTag,
		ReceiverSettings: serial.ToTypedMessage(&proxyman.ReceiverConfig{}),
		ProxySettings: serial.ToTypedMessage(&Config{
			Name: name, Mtu: 1500,
			Address: []string{netip.PrefixFrom(ip4, 30).String(), netip.PrefixFrom(ip6, 126).String()}, UserLevel: 7,
		}),
	}}
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	return instance
}

func kernelDial(t testing.TB, ip netip.Addr, port int) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(ip.Next(), uint16(port)).String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn.(*net.TCPConn)
}

func assertNativeHandoff(t testing.TB) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		traces := make([]byte, 1<<20)
		n := runtime.Stack(traces, true)
		if strings.Contains(string(traces[:n]), "(*tcpConn).ReadFromRaw") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("live native download did not reach the protocol-ready engine handoff")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNativeKernelFDAndRawTransfer(t *testing.T) {
	fd, name, ip4, ip6 := kernelDevice(t)
	port := echoTCP(t)
	for restart := 0; restart < 2; restart++ {
		instance := kernelCore(t, memoryCoreConfig(nil), name, ip4, ip6)
		for _, ip := range []netip.Addr{ip4, ip6} {
			conn := kernelDial(t, ip, port)
			payload := bytes.Repeat([]byte("native-kernel"), 8192)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(payload); written <- err }()
			actual := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, actual); err != nil || !bytes.Equal(actual, payload) {
				t.Fatalf("TCP %s restart %d: %v", ip, restart, err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			assertNativeHandoff(t)
			_ = conn.Close()
		}
		assertCounter(t, instance, "inbound>>>"+integrationTag+">>>traffic>>>downlink", 1)
		live := kernelDial(t, ip4, port)
		if err := instance.Close(); err != nil {
			t.Fatal(err)
		}
		_ = live.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := live.Read(make([]byte, 1)); err == nil {
			t.Fatal("active stream survived core shutdown")
		} else if err, ok := err.(net.Error); ok && err.Timeout() {
			t.Fatal("core shutdown left an active stream blocked")
		}
		_ = live.Close()
		if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("core closed or changed the host-owned descriptor: %v", err)
		}
	}
}

func TestNativeKernelDownloadEOFDoesNotCloseUpload(t *testing.T) {
	_, name, ip4, ip6 := kernelDevice(t)
	kernelCore(t, memoryCoreConfig(nil), name, ip4, ip6)
	payload := bytes.Repeat([]byte("download-half"), 4096)
	results := make(chan error, 2)
	port := serveTCP(t, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		actual := make([]byte, 6)
		if err == nil {
			_, err = io.ReadFull(conn, actual)
		}
		if err == nil && string(actual) != "upload" {
			err = fmt.Errorf("upload after download EOF: %q", actual)
		}
		results <- err
	})
	for _, ip := range []netip.Addr{ip4, ip6} {
		conn := kernelDial(t, ip, port)
		actual, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatalf("native download EOF %s: bytes=%d err=%v", ip, len(actual), err)
		}
		if _, err = conn.Write([]byte("upload")); err != nil {
			t.Fatal("native download EOF closed independent upload: ", err)
		}
		if err = <-results; err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
}

func TestNativeKernelVisionRawHandoff(t *testing.T) {
	_, name, ip4, ip6 := kernelDevice(t)
	fixture := visionCoreConfig(t)
	instance := kernelCore(t, fixture.Config, name, ip4, ip6)
	for _, ip := range []netip.Addr{ip4, ip6} {
		raw := kernelDial(t, ip, int(fixture.Target.Port()))
		conn := tls.Client(raw, fixture.ClientTLS.Clone())
		if err := conn.Handshake(); err != nil {
			t.Fatal(err)
		}
		for _, size := range []int{1, 32768, 1 << 20} {
			payload := bytes.Repeat([]byte{byte(size + 17)}, size)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(payload); written <- err }()
			actual := make([]byte, size)
			if _, err := io.ReadFull(conn, actual); err != nil || !bytes.Equal(actual, payload) {
				t.Fatalf("Vision payload %s size %d: %v", ip, size, err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
		}
		assertNativeHandoff(t)
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if err := raw.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		trailer, err := io.ReadAll(conn)
		if err != nil || string(trailer) != visionCloseReply {
			t.Fatalf("Vision independent half-close: %q %v", trailer, err)
		}
		_ = conn.Close()
	}
	assertCounter(t, instance, "outbound>>>"+visionOutboundTag+">>>traffic>>>downlink", 1)
}
