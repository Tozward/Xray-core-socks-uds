package singtun

import (
	"net/netip"

	"github.com/xtls/xray-core/common/errors"
)

// Validate checks both JSON and direct protobuf callers before native allocation.
func (c *Config) Validate() error {
	if c.Mtu < 576 || c.Mtu > 65535 {
		return errors.New("sing-tun: mtu must be between 576 and 65535")
	}
	for _, address := range c.Address {
		prefix, err := netip.ParsePrefix(address)
		if err != nil {
			return errors.New("sing-tun: invalid address prefix").Base(err)
		}
		ip := prefix.Addr()
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() {
			return errors.New("sing-tun: address must be a unicast IPv4 or IPv6 prefix")
		}
		if ip.Is6() && c.Mtu < 1280 {
			return errors.New("sing-tun: IPv6 requires mtu >= 1280")
		}
	}
	return nil
}
