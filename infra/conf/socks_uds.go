package conf

import (
	"github.com/xtls/xray-core/proxy/socks_uds"
)

type SocksUdsServerConfig struct {
    // 映射 JSON 内该协议可能存在的字段，目前留空即可
}

func (c *SocksUdsServerConfig) Build() (*socks_uds.ServerConfig, error) {
	return &socks_uds.ServerConfig{}, nil
}

func (c *SocksUdsServerConfig) UnmarshalJSON(data []byte) error {
	return nil
}

func init() {
	RegisterInboundConfigCreator("socks_uds", func() Creator {
		return new(SocksUdsServerConfig)
	})
}