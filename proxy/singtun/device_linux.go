//go:build with_sing_tun && linux

package singtun

import (
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func deviceName(fd int) (string, error) {
	request, err := unix.NewIfreq("")
	if err != nil {
		return "", err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, request); err != nil {
		return "", err
	}
	flags := request.Uint16()
	if flags&unix.IFF_TUN == 0 || flags&unix.IFF_NO_PI == 0 {
		return "", errors.New("TUN must use IFF_TUN and IFF_NO_PI")
	}
	if flags&unix.IFF_VNET_HDR != 0 {
		size, err := unix.IoctlGetInt(fd, unix.TUNGETVNETHDRSZ)
		if err != nil || size != 10 {
			return "", errors.New("unsupported virtio network header size").Base(err)
		}
	}
	return request.Name(), nil
}
