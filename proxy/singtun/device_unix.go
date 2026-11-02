//go:build with_sing_tun && (linux || darwin)

package singtun

import (
	"runtime"
	"strconv"

	stun "github.com/sagernet/sing-tun"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"golang.org/x/sys/unix"
)

func openDevice(options *stun.Options) (stun.Tun, error) {
	value := platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" })
	if value == "" {
		if runtime.GOOS == "android" || runtime.GOOS == "ios" {
			return nil, errors.New("sing-tun: host must supply ", platform.TunFdKey)
		}
		if options.Name == "" {
			return nil, errors.New("sing-tun: device name is required")
		}
		return stun.New(*options)
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 3 {
		return nil, errors.New("sing-tun: ", platform.TunFdKey, " must be a descriptor >= 3")
	}
	if options.GSO || options.MultiQueue {
		return nil, errors.New("sing-tun: supplied descriptor offload and queues belong to the host")
	}
	name, err := deviceName(fd)
	if err != nil {
		return nil, errors.New("sing-tun: invalid supplied TUN descriptor").Base(err)
	}
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(duplicate, true); err != nil {
		_ = unix.Close(duplicate)
		return nil, err
	}
	options.FileDescriptor = duplicate
	options.Name = name
	device, err := stun.New(*options)
	if err != nil {
		_ = unix.Close(duplicate)
	}
	return device, err
}
