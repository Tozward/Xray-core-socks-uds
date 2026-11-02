//go:build with_sing_tun && darwin

package singtun

import "golang.org/x/sys/unix"

func deviceName(fd int) (string, error) {
	return unix.GetsockoptString(fd, 2, 2) // SYSPROTO_CONTROL / UTUN_OPT_IFNAME.
}
