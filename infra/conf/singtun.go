package conf

import (
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/singtun"
	"google.golang.org/protobuf/proto"
)

type SingTunConfig struct {
	Name          string   `json:"name"`
	MTU           uint32   `json:"mtu"`
	Address       []string `json:"address"`
	UserLevel     uint32   `json:"userLevel"`
	GSO           bool     `json:"gso"`
	MultiQueue    bool     `json:"multiQueue"`
	TCPLocalJumbo bool     `json:"tcpLocalJumbo"`
}

func (c *SingTunConfig) Build() (proto.Message, error) {
	if !singtun.Enabled {
		return nil, errors.New("sing-tun support is not included; build with -tags with_sing_tun")
	}
	config := &singtun.Config{
		Name: c.Name, Mtu: c.MTU, Address: append([]string(nil), c.Address...),
		UserLevel: c.UserLevel, Gso: c.GSO, MultiQueue: c.MultiQueue, TcpLocalJumbo: c.TCPLocalJumbo,
	}
	if config.Mtu == 0 {
		config.Mtu = 1500
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Name == "" {
		name, err := GetAvailableTunName()
		if err != nil {
			return nil, err
		}
		config.Name = name
	}
	return config, nil
}
