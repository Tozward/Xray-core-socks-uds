package conf

import (
	"github.com/xtls/xray-core/proxy/socks_uds"
	"google.golang.org/protobuf/proto"
)

type SocksUdsServerConfig struct {
	// 映射 JSON 内该协议可能存在的字段，目前无特殊字段，留空
}

func (c *SocksUdsServerConfig) Build() (proto.Message, error) {
	return &socks_uds.ServerConfig{}, nil
}