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

## Measured comparison

[Verification run 41414853301](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41414853301)
tests implementation `fca55ba917df7919439897d0d462652cf559a64c`. Default and
tagged focused regressions, race checks and CLI builds pass on Linux, macOS and
Windows. Linux additionally runs actual TUN descriptor/restart, download EOF
with independent upload, and verified TLS 1.3 Vision handoff tests three times.
The separate dependency regression run is
[41411565431](https://github.com/Tozward/sing-tun/actions/runs/41411565431).

The Linux amd64 benchmark uses an AMD EPYC 7763 with GOMAXPROCS=4, MTU 1500 and
no GSO. Each operation uploads 4 MiB and reads its 4 MiB echo. All rows use the
same stack, Xray outbound and counters; Vision also uses the same verified local
node and inner TLS application. Setup and handshakes are excluded. Every Vision
case must complete its actual command-2 transitions before bulk warmup. Logging
is disabled while measuring. Values below are per-metric medians of three
two-second samples; throughput is aggregate duplex, CPU includes all local
client/node/application threads, and B/op measures allocations, not live RSS.

| Outbound | Path | MB/s | CPU ms/op | B/op |
| --- | --- | ---: | ---: | ---: |
| freedom | SOCKS + full engine Splice | 291.53 | 55.97 | 157359 |
| freedom | Native Read/Write | 339.65 | 64.54 | 201072 |
| freedom | Native download handoff | 312.52 | 53.64 | 342691 |
| Vision TLS 1.3 | SOCKS + full engine Splice | 281.31 | 76.14 | 289838 |
| Vision TLS 1.3 | Native Read/Write | 325.88 | 73.34 | 271510 |
| Vision TLS 1.3 | Native download handoff | 300.80 | 68.06 | 418115 |

These samples show a throughput/CPU/allocation tradeoff, not a universal winner.
The native handoff uses less CPU here but allocates more bytes; ordinary native
I/O reaches greater throughput. Neither comparison measures HEV, Android/ARM,
idle wakeups, mobile radio energy, WAN performance or many concurrent flows.
Keep alternative paths and defaults available until target-device measurements
justify changing them. The native handoff remains conditional on protocol
readiness and platform support.

The earlier benchmark artifact from run 41413298407 is invalid for performance
conclusions: some Vision connections remained framed and two handoff assertions
failed. It is excluded. The final workflow rejects failed subcases and requires
all 18 measured rows, in addition to checking the process exit status.

### HEV comparison and path names

The three original rows combine two separate dimensions: how the stack enters
Xray and how TCP bytes are moved. They are not three APK selector entries.

| Benchmark path | Packet/stream path | APK VPN choice |
| --- | --- | --- |
| SOCKS + full engine Splice | TUN → sing-tun NewGo → loopback SOCKS → Xray dispatcher/outbound | Sing TUN |
| Native Read/Write | TUN → NewGo inside Xray → dispatcher/outbound, ordinary pooled-buffer reads/writes | Sing native TUN, ordinary phase; benchmark disables optional handoff |
| Native download handoff | Same direct dispatcher path; eligible raw download socket is read by the native engine | Sing native TUN, conditional TCP optimization |
| HEV | TUN → HEV/lwIP → loopback SOCKS → Xray dispatcher/outbound | HEV TUN |

The native APK option starts with normal I/O and uses download handoff only
after Xray permits it. Upload retains Xray processing. Unsupported conditions
keep normal I/O. UDP uses its own adapter and is not a SpliceDownload path.
The APK preserves the previously saved backend; installing it does not select
Sing native automatically.

[HEV comparison run 41424113515](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41424113515)
adds the APK-pinned HEV `c5584feca8f6df70ee53eb2879e034b849a3d15a` (2.19.3).
It uses a small library runner borrowing the same no-virtio-header TUN fd, not
the stock executable, which would create/configure a different TUN. Total CPU
includes both the Go process and HEV child process. Go B/op does not include HEV
C allocations and must not be used as a total-memory comparison.

This run uses Linux amd64 AMD EPYC 9V45, GOMAXPROCS=4, configured MTU1500 and
the same verified Vision fixture/workload as above. Its CPU model differs from
the earlier run; compare rows within this run, not absolute values across runs.
Each value is the median of three two-second samples, 4MiB upload + 4MiB echo.

| Path | freedom MB/s | freedom CPU ms/op | Vision MB/s | Vision CPU ms/op |
| --- | ---: | ---: | ---: | ---: |
| HEV, Android defaults | 688.54 | 20.64 | 657.58 | 33.92 |
| HEV, jumbo disabled | 225.37 | 38.84 | 207.08 | 50.59 |
| Sing via SOCKS/full engine Splice | 483.35 | 35.24 | 449.39 | 46.24 |
| Sing direct/ordinary I/O | 533.82 | 41.72 | 496.90 | 47.07 |
| Sing direct/eligible download handoff | 411.80 | 36.92 | 416.74 | 43.27 |

HEV's actual Android config omits offload options. At this pin, a supplied TUN
without IFF_VNET_HDR still retains its default local jumbo support, so configured
MTU1500 does not mean every injected TCP packet is <=1500 bytes. The separate
jumbo-disabled row sets tso/uso/jumbo=false; it must not replace the app-default
row or be presented as actual APK defaults. This implementation detail has a
large impact here. Default HEV wins both throughput and CPU in this workload;
the new native implementation is not established as an HEV performance upgrade.
Android/ARM energy, UDP, idle wakeups, WAN latency and many-flow behavior remain
unmeasured. This update changes benchmarks/documentation only; the delivered APK
and its runtime core remain unchanged. The extended workflow requires all 30
measurements and rejects failed subcases.

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
