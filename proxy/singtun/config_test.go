package singtun

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "external_addresses", config: Config{Mtu: 1500}},
		{name: "minimum_ipv4_mtu", config: Config{Mtu: 576, Address: []string{"10.0.0.1/24"}}},
		{name: "minimum_ipv6_mtu", config: Config{Mtu: 1280, Address: []string{"fd00::1/64"}}},
		{name: "maximum_mtu", config: Config{Mtu: 65535, Address: []string{"10.0.0.1/24", "fd00::1/64"}}},
		{name: "zero_mtu", config: Config{}, wantErr: true},
		{name: "small_mtu", config: Config{Mtu: 575}, wantErr: true},
		{name: "excessive_mtu", config: Config{Mtu: 65536}, wantErr: true},
		{name: "ipv6_small_mtu", config: Config{Mtu: 1279, Address: []string{"fd00::1/64"}}, wantErr: true},
		{name: "malformed_prefix", config: Config{Mtu: 1500, Address: []string{"10.0.0.1"}}, wantErr: true},
		{name: "malformed_address", config: Config{Mtu: 1500, Address: []string{"bad/24"}}, wantErr: true},
		{name: "invalid_prefix_length", config: Config{Mtu: 1500, Address: []string{"10.0.0.1/33"}}, wantErr: true},
		{name: "unspecified_ipv4", config: Config{Mtu: 1500, Address: []string{"0.0.0.0/0"}}, wantErr: true},
		{name: "unspecified_ipv6", config: Config{Mtu: 1500, Address: []string{"::/0"}}, wantErr: true},
		{name: "multicast_ipv4", config: Config{Mtu: 1500, Address: []string{"224.0.0.1/24"}}, wantErr: true},
		{name: "multicast_ipv6", config: Config{Mtu: 1500, Address: []string{"ff02::1/64"}}, wantErr: true},
		{name: "mapped_ipv4", config: Config{Mtu: 1500, Address: []string{"::ffff:10.0.0.1/120"}}, wantErr: true},
	}
	for index := range tests {
		test := &tests[index]
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() = %v, want error %v", err, test.wantErr)
			}
		})
	}
}
