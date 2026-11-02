package proxy

import (
	"net"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// rawUplinkSocket only permits the known wrappers at a protocol-ready upload
// boundary. TcpMaskConn.Splice returning true does not establish upload-write
// transparency: a client fragment mask can still transform later writes.
// This guard limits the new handoff without changing the existing copier or
// its unwrap contract, and never bypasses an unknown transport.
func rawUplinkSocket(conn net.Conn) bool {
	for {
		switch current := conn.(type) {
		case finalmask.TcpMaskConn:
			return false
		case *encryption.CommonConn:
			conn = current.Conn
		case *stat.CounterConnection:
			conn = current.Connection
		case *tls.Conn:
			conn = current.NetConn()
		case *tls.UConn:
			conn = current.NetConn()
		case *reality.Conn:
			conn = current.NetConn()
		case *reality.UConn:
			conn = current.NetConn()
		case *proxyproto.Conn:
			conn = current.Raw()
		case *internet.UnixConnWrapper:
			conn = current.UnixConn
		case *net.TCPConn:
			return true
		case *net.UnixConn:
			peer := current.RemoteAddr()
			return peer != nil && peer.Network() == "unix"
		default:
			return false
		}
	}
}
