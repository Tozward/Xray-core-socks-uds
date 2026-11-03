//go:build with_sing_tun && linux && !android

package singtun

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// Request asynchronous ICMP errors explicitly: Linux otherwise ignores soft
// host-unreachable errors on ordinary UDP reads. This verifies the TUN/kernel
// feedback contract, not a browser-specific fallback timer. No remote network.
func TestNativeKernelUDP443RejectionReachesErrorReceiver(t *testing.T) {
	fixture := visionCoreConfig(t)
	_, name, ip4, ip6 := kernelDeviceMTU(t, 9000)
	kernelCoreMTU(t, fixture.Config, name, ip4, ip6, 9000)
	for _, test := range []struct {
		network string
		address net.IP
	}{
		{"udp4", net.IP(ip4.Next().AsSlice())},
		{"udp6", net.IP(ip6.Next().AsSlice())},
	} {
		t.Run(test.network, func(t *testing.T) {
			conn, err := net.DialUDP(test.network, nil, &net.UDPAddr{IP: test.address, Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			control, err := conn.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var socketErr error
			if err := control.Control(func(fd uintptr) {
				level, option := syscall.IPPROTO_IP, syscall.IP_RECVERR
				if test.network == "udp6" {
					level, option = syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR
				}
				socketErr = syscall.SetsockoptInt(int(fd), level, option, 1)
			}); err != nil {
				t.Fatal(err)
			}
			if socketErr != nil {
				t.Fatal(socketErr)
			}
			if err := conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if _, err := conn.Write([]byte("controlled rejected datagram")); err != nil {
				t.Fatal(err)
			}
			_, err = conn.Read(make([]byte, 128))
			if !errors.Is(err, syscall.EHOSTUNREACH) && !errors.Is(err, syscall.ENETUNREACH) {
				t.Fatalf("initial rejection did not reach host socket: %v", err)
			}
			t.Logf("socket received local unreachable after %s", time.Since(started))
		})
	}
}
