package socks_uds

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestServerNegotiatesOnlyOfferedNoAuth(t *testing.T) {
	for _, test := range []struct {
		name    string
		methods []byte
	}{
		{"empty", nil}, {"password", []byte{2}}, {"no_auth", []byte{0}}, {"mixed", []byte{2, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			methods := test.methods
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- (&Server{policyManager: policy.DefaultManager{}}).Process(context.Background(), xnet.Network_TCP, server, nil)
			}()
			greeting := append([]byte{5, byte(len(methods))}, methods...)
			if _, err := client.Write(greeting); err != nil {
				t.Fatal(err)
			}
			var reply [2]byte
			if _, err := io.ReadFull(client, reply[:]); err != nil {
				t.Fatal(err)
			}
			method := byte(0xff)
			if bytes.IndexByte(methods, 0) >= 0 {
				method = 0
			}
			if reply != [2]byte{5, method} {
				t.Fatalf("selected an unoffered method: %v", reply)
			}
			_ = client.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("incomplete or rejected handshake reported success")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("server retained the closed handshake")
			}
		})
	}
}

type handshakePolicy struct {
	policy.DefaultManager
	timeout time.Duration
}

func (p handshakePolicy) ForLevel(uint32) policy.Session {
	value := policy.SessionDefault()
	value.Timeouts.Handshake = p.timeout
	return value
}

func TestServerBoundsIncompleteHandshake(t *testing.T) {
	for _, cancelContext := range []bool{false, true} {
		name := "policy_timeout"
		if cancelContext {
			name = "context_cancel"
		}
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager := policy.Manager(handshakePolicy{timeout: 10 * time.Millisecond})
			if cancelContext {
				manager = policy.DefaultManager{}
			}
			done := make(chan error, 1)
			go func() { done <- (&Server{policyManager: manager}).Process(ctx, xnet.Network_TCP, server, nil) }()
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Write([]byte{5}); err != nil && cancelContext {
				t.Fatal(err)
			}
			if cancelContext {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("incomplete handshake reported success")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("incomplete handshake outlived its timeout or cancellation")
			}
		})
	}
}

func TestServerClearsHandshakeDeadlineForTCPRelay(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer := pipe.New()
	dispatcher := &associationDispatcher{link: &transport.Link{Reader: reader, Writer: writer}, seen: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- (&Server{policyManager: handshakePolicy{timeout: time.Second}}).Process(ctx, xnet.Network_TCP, server, dispatcher)
	}()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(client, method[:]); err != nil || method != [2]byte{5, 0} {
		t.Fatalf("handshake: %v %v", method, err)
	}
	if _, err := client.Write([]byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0 {
		t.Fatalf("connect: %v %v", reply, err)
	}
	time.Sleep(1100 * time.Millisecond)
	payload := []byte("relay after handshake deadline")
	if _, err := client.Write(payload); err != nil {
		t.Fatal("handshake deadline closed the established relay: ", err)
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(client, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("established relay: %q %v", received, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("closed TCP relay retained copy tasks")
	}
}
