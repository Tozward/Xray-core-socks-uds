//go:build with_sing_tun && !linux && !darwin

package singtun

import (
	stun "github.com/sagernet/sing-tun"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
)

func openDevice(options *stun.Options) (stun.Tun, error) {
	if platform.NewEnvFlag(platform.TunFdKey).GetValue(func() string { return "" }) != "" {
		return nil, errors.New("sing-tun: supplied file descriptors are unsupported on this platform")
	}
	return stun.New(*options)
}
