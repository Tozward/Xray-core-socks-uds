# Optional native sing-tun inbound

The `sing-tun` inbound connects SagerNet's `NewGo` IP stack directly to Xray's
dispatcher. It is enabled only by the `with_sing_tun` build tag. It does not start
a SOCKS listener, embed sing-box, or insert forwarding pipes between the stacks.
The existing `tun` inbound and TCP kernel-splice path remain available.

The root module pins the independently maintained
[dependency fork](https://github.com/Tozward/sing-tun/tree/feature/xray-native-tun)
at `b65f5e94c698d7bea70950fdcc54dd3cb1514a58`. No local checkout is needed to
build it. The original upstream revision alone does not provide `SpliceDownload`.

## Examined baselines and dependencies

| Component | Examined reference |
| --- | --- |
| Xray upstream | `7c8dbcb4bbec7f80d16070069e0b2f7bf3aca62c` |
| Existing SOCKS UDS extension merged onto that baseline | `189fba66acd8da2fa9c2b8df14f798a9a02c1b50` |
| `github.com/sagernet/sing-tun` | `v0.9.7-0.20261023115453-611d83b7a57b`, commit `611d83b7a57b4719be45581eb674942ff561de6c` |
| `github.com/sagernet/sing` | `v0.9.7-0.20261023115510-03a6cce64bf7`, commit `03a6cce64bf744023af9e2691fb11afd405b9061` |
| Local sing-tun dependency | `github.com/Tozward/sing-tun v0.9.7-0.20261102081331-b65f5e94c698` |

The SagerNet pins were selected from sing-box `v1.15.0-alpha.13`; sing-box is
provenance, not a runtime dependency. Reviewed alternatives included the existing
Xray TUN stack, a TUN-to-SOCKS TCP/UDS bridge, direct `NewGo` connections, and
native socket handoff. This implementation keeps Xray routing and protocol
processing while using direct connections and eligible download handoff.

Xray's repository [license](../LICENSE) is MPL-2.0. The optional backend links
[sing-tun](https://github.com/SagerNet/sing-tun/blob/611d83b7a57b4719be45581eb674942ff561de6c/LICENSE)
and [sing](https://github.com/SagerNet/sing/blob/03a6cce64bf744023af9e2691fb11afd405b9061/LICENSE),
whose notices specify GPL-3.0-or-later. Enabling this tag explicitly includes
that GPL-licensed code; a tagged distribution must carry the applicable notices
and corresponding source obligations. The default build excludes this backend
and rejects `protocol: "sing-tun"` with a build-tag error.

## Data path and ownership

[`proxy/singtun`](../proxy/singtun/handler.go) owns the device, stack, lifecycle
context and active flow callbacks. It reuses
[`tun.Handler.HandleConnectionContext`](../proxy/tun/handler.go) for session
metadata, inbound policy/statistics, sniffing, access logging and synchronous
`DispatchLink`. It does not start a second Xray TUN device.

- **TCP before raw readiness:** native `GoConn.Read` fills Xray pooled buffers;
  writes enter native send storage through `GoConn.Write`. These operations
  include copies. There is no end-to-end zero-copy claim.
- **Eligible raw TCP download:** after the existing freedom/Vision readiness
  checks, including Vision padding removal and draining prefetched TLS bytes,
  `CopyRawConnIfExist` can call the optional `RawReaderFrom` interface.
  [`tcpConn`](../proxy/singtun/tcp.go) invokes the local dependency's
  `GoConn.SpliceDownload`: the engine reads a duplicated raw TCP/stream-UDS
  descriptor directly into native send storage. Upload continues through normal
  Xray processing and the original socket. EOF releases the duplicate and
  completes the download half independently; cancellation closes the owned
  native connection. Counter wrappers and activity updates remain in this path.
- **UDP:** mappings depend on client and destination address/port, giving each
  destination its own routing decision. Reply filtering is endpoint-independent.
  Uplink packets are copied once into Xray-owned buffers with independent
  per-packet destination metadata. MTU-fit downlink batches borrow payload views
  only for the synchronous native write; oversized packets and non-batch writers
  receive owned buffers with header space. Xray's FakeDNS endpoint restoration
  and valid alternate reply-source addresses are preserved.

SagerNet's full `GoConn.Splice` is bidirectional engine-owned socket I/O. Neither
it nor `SpliceDownload` means Linux `splice(2)`. The existing TCP kernel-splice
branch in Xray is separate and unchanged. There is no evidence here that a
two-way handoff is faster, or that sing-tun is universally faster than another
stack or a SOCKS bridge. Compare eligible raw, encrypted and multiplexed paths
separately on the target platform.

## Configuration and host responsibilities

This is a portless inbound; omit `listen` and `port`. A minimal example is:

```json
{
  "tag": "native-tun",
  "protocol": "sing-tun",
  "settings": {
    "mtu": 1500,
    "address": ["172.19.0.1/30"]
  }
}
```

`address` supplies stack metadata and must match the host's configuration; it
does not assign interface addresses. Keep `mtu` aligned with the actual device.
It defaults to 1500 in JSON and must be
576–65535; configured IPv6 requires at least 1280. Optional fields are `name`,
`userLevel`, `gso` and `multiQueue`. Native device creation uses platform names
(for example, `utunN` on Darwin). Unsupported protocol traffic, including ICMP,
is rejected rather than sent through a direct native bypass.

The host owns interface addresses, routes, DNS configuration and outbound socket
protection/binding. The backend sets `EXP_ExternalConfiguration` and disables
native DNS hijacking. Owned native devices still configure their MTU, up state
and requested offload; supplied Darwin devices also configure native pending
packet limits. Route DNS through Xray explicitly when required; configure
Xray FakeDNS/sniffing using the existing Xray settings. Android VPN and Apple
Network Extension integrations must keep Xray's own outbound connections outside
the captured path. Supplying a TUN descriptor alone does not prevent a routing
loop.

On Linux/Android and Darwin/iOS, the host may supply `XRAY_TUN_FD` (also accepted
as `xray.tun.fd`). Android/iOS require it. The descriptor must be at least 3 and
refer to the appropriate TUN/utun device. The core validates its device name,
duplicates it with close-on-exec, and owns only that duplicate. Failure and
shutdown close the duplicate, preserving the caller's descriptor. The duplicate
shares file status flags: setting nonblocking mode also affects the original.
The host must not concurrently consume packets from the same TUN queue.

Linux descriptors require `IFF_TUN | IFF_NO_PI`; a virtio header, if present,
must be 10 bytes. `gso` and `multiQueue` must be false for supplied descriptors:
their queue/offload configuration belongs to the host. Supplied descriptors are
rejected on other platforms; native creation there is subject to the dependency's
platform support and privileges.

## Building and delivering the dependency

Use Go 1.27 or newer; development verification used Go 1.27.3. Execute from the
Xray checkout to build the optional backend:

```sh
go build -tags with_sing_tun -o xray ./main
```

Applications embedding Xray must apply the tag to their own build. A library's
`replace` directives do not propagate into the consuming application's module.
The final consuming module therefore needs its own replacement for this patched
dependency, or an equivalent workspace during development.

Apply this exact replacement in an embedding consumer's root `go.mod` as well:

```go
replace github.com/sagernet/sing-tun => github.com/Tozward/sing-tun v0.9.7-0.20261102081331-b65f5e94c698
```

Do not publish a build that silently resolves to the unpatched upstream pin or
depends on an unrecorded local checkout. Record the fork revision and dependency
checksums together when preparing the release pin.

## Validation and upstream updates

Packet ownership, destination isolation, FakeDNS, counters, cancellation and
Vision integration have focused tests in `proxy/singtun`. Dependency socket tests
cover download EOF while upload remains open, descriptor ownership, closed-window
backpressure and full-splice regression. Privileged native TUN tests are a
separate gate; compilation or a skipped privileged test does not validate that
path. Packet adapter microbenchmarks do not establish end-to-end throughput or
CPU improvement. Existing Xray copy paths do not forward zero-length UDP packets.

Maintain the dependency independently using its
[patch ledger](https://github.com/Tozward/sing-tun/blob/b65f5e94c698d7bea70950fdcc54dd3cb1514a58/docs/xray-integration-patches.md).
The ledger separates constructor
fixes `ST-FD-001`–`ST-FD-004` from download API extension `ST-API-001`.

For each upstream update, inspect the affected official code and run each ledger
regression against clean upstream without the local implementation patch. Prefer
an official fix that passes the complete regression; remove superseded local
hunks and retain only unresolved differences. Record retirement evidence in the
ledger rather than mechanically choosing local code during conflicts. Recheck
the raw-download API, EOF/cancellation, UDP ownership/MTU and platform descriptor
contracts; then run both default and tagged Xray tests, dependency platform tests,
privileged TUN tests and target-platform performance comparisons. Update the
immutable fork pin, checksums and this document together.
