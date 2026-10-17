package reality

import "testing"

func TestGetREALITYConfigKeyValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{name: "invalid X25519", config: &Config{PrivateKey: make([]byte, 31)}, wantErr: true},
		{name: "invalid ML-DSA seed", config: &Config{PrivateKey: make([]byte, 32), Mldsa65Seed: make([]byte, 31)}, wantErr: true},
		{name: "X25519 only", config: &Config{PrivateKey: make([]byte, 32)}},
		{name: "X25519 and ML-DSA", config: &Config{PrivateKey: make([]byte, 32), Mldsa65Seed: make([]byte, 32)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := test.config.GetREALITYConfig()
			if test.wantErr {
				if err == nil || config != nil {
					t.Fatalf("invalid key accepted: config=%v, err=%v", config != nil, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if config.PrivateKey == nil || (test.config.Mldsa65Seed != nil && config.Mldsa65Key == nil) {
				t.Fatal("parsed private key is missing")
			}
		})
	}
}
