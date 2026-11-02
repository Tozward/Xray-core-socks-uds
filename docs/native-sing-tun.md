# Optional native sing-tun inbound

The `sing-tun` inbound connects SagerNet's `NewGo` IP stack directly to Xray's
dispatcher. It is enabled only by the `with_sing_tun` build tag. It does not start
a SOCKS listener, embed sing-box, or insert forwarding pipes between the stacks.
The existing `tun` inbound and TCP kernel-splice path remain available.

The root module pins the independently maintained
[dependency fork](https://github.com/Tozward/sing-tun/tree/feature/xray-native-tun)
at `9af120bbf52457f6c946e4d63587c2bfed57e07e`. No local checkout is needed to
build it. The original upstream revision alone does not provide the directional APIs.
The [patch ledger](https://github.com/Tozward/sing-tun/blob/9af120bbf52457f6c946e4d63587c2bfed57e07e/docs/xray-integration-patches.md)
keeps constructor fixes, directional handoff, borrowed vectors and local aggregation
separate, with upstream-first retirement criteria.

## Examined baselines and dependencies

| Component | Examined reference |
| --- | --- |
| Xray upstream | `7c8dbcb4bbec7f80d16070069e0b2f7bf3aca62c` |
| Existing SOCKS UDS extension merged onto that baseline | `189fba66acd8da2fa9c2b8df14f798a9a02c1b50` |
| `github.com/sagernet/sing-tun` | `v0.9.7-0.20261023115453-611d83b7a57b`, commit `611d83b7a57b4719be45581eb674942ff561de6c` |
| `github.com/sagernet/sing` | `v0.9.7-0.20261023115510-03a6cce64bf7`, commit `03a6cce64bf744023af9e2691fb11afd405b9061` |
| Local sing-tun dependency | `github.com/Tozward/sing-tun v0.9.7-0.20261102183854-9af120bbf524` |

The SagerNet pins were selected from sing-box `v1.15.0-alpha.13`; sing-box is
provenance, not a runtime dependency. Reviewed alternatives included the existing
Xray TUN stack, a TUN-to-SOCKS TCP/UDS bridge, direct `NewGo` connections, and
native socket handoff. This implementation keeps Xray routing and protocol
processing while using direct connections and independently eligible raw handoff.

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
  writes borrow multi-buffer slices through `GoConn.WriteVector`, entering the
  writer once per batch and copying into its existing retransmission storage.
  No Xray buffer is retained or transferred into another pool. These operations
  include copies. There is no end-to-end zero-copy claim.
- **Eligible raw TCP download:** after the existing freedom/Vision readiness
  checks, including Vision padding removal and draining prefetched TLS bytes,
  `CopyRawConnIfExist` can call the optional `RawReaderFrom` interface.
  [`tcpConn`](../proxy/singtun/tcp.go) invokes the local dependency's
  `GoConn.SpliceDownload`: the engine reads a duplicated raw TCP/stream-UDS
  descriptor directly into native send storage. EOF completes only the download
  half; cancellation closes the owned native connection. Counter wrappers and
  activity updates remain in this path.
- **Eligible raw TCP upload:** freedom without fragmentation, or Vision after a
  successful final command-2 padding write and header flush, can use
  `CopyRawUplink` / `RawWriterTo`. The uploader observes its own readiness after
  a complete ordinary read/write batch; it never polls download state. Sniff and
  timed-read caches must be empty before forwarding the handoff. `SpliceUpload`
  sends native receive storage directly to the same raw socket, with independent
  completion and half-close. Either direction may attach or finish first.
- **Optional local TCP aggregation:** `tcpLocalJumbo` defaults to false. An
  explicit Linux/Android local-delivery configuration permits TCP data aggregates
  on verified plain TUN devices, only to an exact configured interface address.
  Callers must prevent forwarding/NAT of these replies. Software checksums,
  bounded packet sizes, unchanged MSS/congestion units and loss/error fallback
  preserve the ordinary TCP contract. UDP and virtio/GSO devices are unchanged.
- **UDP:** mappings depend on client and destination address/port, giving each
  destination its own routing decision. Reply filtering is endpoint-independent.
  Uplink packets are copied once into Xray-owned buffers with independent
  per-packet destination metadata. MTU-fit downlink batches borrow payload views
  only for the synchronous native write; oversized packets and non-batch writers
  receive owned buffers with header space. Xray's FakeDNS endpoint restoration
  and valid alternate reply-source addresses are preserved.

SagerNet's full `GoConn.Splice` is bidirectional engine-owned socket I/O. Neither
it nor the directional APIs mean Linux `splice(2)`. The existing TCP kernel-splice
branch in Xray is separate and unchanged. There is no evidence here that a
two-way handoff is faster, or that sing-tun is universally faster than another
stack or a SOCKS bridge. Compare eligible raw, encrypted and multiplexed paths
separately on the target platform.

## Verified bidirectional handoff and local aggregation

Runtime implementation: `eb5310947c46520eeba7981b8711feb5f8ed9b1a`.
Verification source: `cdd71da026a0deb6ef0d5130d266a8218979c724`; its only
changes after the runtime commit are three test files. The Android candidate
pins the runtime commit, avoiding an AAR rebuild for test-only changes.
Dependency features are isolated in `22c7747ac677814e46dfd193f2046425c1877794`,
with the final tested dependency pin `3855ec8dcf9cb1eb3036d334b1ecd5be89b14334`.
The dependency ledger keeps ST-FD constructor fixes distinct from ST-API-002
(directional handoff), ST-API-003 (borrowed vectors) and ST-PERF-001 (local TCP
aggregation), each with its own upstream-first replacement criteria.

[Core verification](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41450401671)
and [dependency verification](https://github.com/Tozward/sing-tun/actions/runs/41448766157)
pass on Linux, macOS and Windows. Linux additionally repeats real-TUN direction,
Vision, ownership, IPv4/IPv6, aggregation and loss-recovery checks three times.
The default Xray binary still excludes the optional Sing dependencies.

[Complete profiling run](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41450436595)
contains 51 cases / 153 uninstrumented rows and separate CPU diagnostics.
One AMD EPYC 7763 runner, Linux/amd64, Go1.27.3, GOMAXPROCS=4, actual MTU9000.
Each row below is the per-metric median of three two-second measurements, with
4MiB upload plus its 4MiB echo per operation. Throughput is aggregate duplex;
CPU includes the client, local application, local Vision node and HEV child.
Go allocation metrics exclude HEV's C heap. Setup, protocol transition, packet
observation and profiling are outside the uninstrumented measurement intervals.

| Path | freedom MB/s | freedom CPU ms/op | Vision MB/s | Vision CPU ms/op |
| --- | ---: | ---: | ---: | ---: |
| HEV, Android defaults / jumbo | 748.81 | 30.21 | 705.54 | 39.34 |
| Sing via SOCKS, no local jumbo | 766.37 | 31.09 | 641.04 | 41.73 |
| Sing via SOCKS, local jumbo | 785.13 | 29.53 | 653.30 | 40.11 |
| Native legacy sequential Read/Write | 697.42 | 32.82 | 606.12 | 43.58 |
| Native legacy download-only handoff | 543.35 | 31.30 | 613.99 | 41.44 |
| Native vector writes, no handoff | 734.86 | 30.80 | 640.02 | 41.41 |
| Native bidirectional handoff | 1125.79 | 12.82 | 886.07 | 32.25 |
| Native bidirectional handoff + local jumbo | 1458.57 | 9.45 | 931.99 | 30.80 |

Legacy controls deliberately hide the new raw capabilities and retain their old
8KiB sequential adapter. The vector, directional and jumbo paths are separately
named. Every enabled direction must report actual bulk handoff bytes. Every
jumbo case observes a real 53740-byte local IP packet during warmup; its observer
is closed and joined before timing. The upload-only workload uses a separate
verified download warmup, since its ordinary completion reply is just one byte.

The one-way freedom upload changes from 481.96MB/s / 21.33ms CPU / 1632 Go
allocations per 4MiB in the old download-only integration to 1337.99MB/s /
6.04ms / 64 allocations with bidirectional handoff and jumbo. The standalone
engine upload control reaches 1350.09MB/s / 5.99ms / 64 allocations in this run.
This isolates removal of the old Xray upload conversion. Borrowed vector writes
also improve the ordinary download fallback without transferring buffer ownership.

These are local Linux measurements, not Android power measurements. The optimized
native path has higher duplex throughput and lower duplex CPU than HEV here;
Vision download alone is close to SOCKS+jumbo (648.71 vs 642.85MB/s) and its CPU
is slightly higher than HEV (10.77 vs 10.62ms per 4MiB). Small differences do not
establish a winner. Raw readiness remains conditional, and unchanged encrypted,
fragmented, multiplexed or unsupported paths keep their ordinary copier. No
background polling, automatic backend switch or new tuning UI is introduced.

Without local aggregation, the Vision download-only workload is a tradeoff:
bidirectional handoff measures 505.52MB/s / 14.44ms CPU against the old download
handoff's 551.44MB/s / 15.12ms. This does not justify a universal speed claim.
CPU samples no longer contain the native client's old upload `buf.Copy` /
`GoConn.Read` chain. Remaining Vision upload copies are in the local fixture's
server-side freedom outbound, with additional application TLS work. These
profiles support removal of that client conversion, not end-to-end zero-copy.

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

The native APK option starts with normal I/O and hands over each direction only
after Xray permits it. Unsupported conditions
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

### Matched virtual MTU follow-up

[Run 41427523421](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41427523421)
tests benchmark source `e47eddce6a613926716c1ba0a64b6d8df10a8b71` at both
MTU1500 and MTU9000. This run uses Linux amd64 Intel Xeon Platinum 8370C,
GOMAXPROCS=4. Compare rows within this run; its CPU differs from both earlier runs.
The workload remains 4MiB upload plus 4MiB echo per operation, three two-second
samples, verified Vision readiness, and quiet steady-state measurement. All 20
cases produced three successful measurements. Default/tagged focused checks,
race/vet, builds and official format/protobuf checks also passed.

Both the actual TUN interface and each stack receive the named MTU. Each
connection asserts and reports its kernel path MTU and negotiated TCP MSS.
HEV's own constructor/config-file default is 8500, but v2rayNG's TProxyService
always emits `tunnel.mtu` from the GUI setting (default1500), overriding that
library default. The MTU9000 rows explicitly set 9000 for HEV as well as Sing;
they are not a comparison between HEV8500 and Sing9000.
Pinned HEV/lwIP caps advertised MSS at 8191, so its measured MSS is 1460/8191;
Sing negotiates 1448/8948, including its timestamp option. Those implementation
differences are retained rather than changing the production HEV build.

| MTU | Path | freedom MB/s | freedom CPU ms/op | Vision MB/s | Vision CPU ms/op |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1500 | HEV, Android defaults | 678.85 | 23.39 | 599.83 | 40.80 |
| 9000 | HEV, Android defaults | 1096.06 | 19.19 | 913.22 | 29.81 |
| 1500 | HEV, jumbo disabled | 237.31 | 37.50 | 222.79 | 56.38 |
| 9000 | HEV, jumbo disabled | 301.35 | 23.27 | 324.74 | 32.75 |
| 1500 | Sing via SOCKS/full engine Splice | 413.62 | 37.99 | 414.56 | 53.35 |
| 9000 | Sing via SOCKS/full engine Splice | 1109.61 | 20.29 | 848.30 | 32.02 |
| 1500 | Sing direct/ordinary I/O | 526.56 | 41.13 | 482.20 | 51.03 |
| 9000 | Sing direct/ordinary I/O | 980.99 | 21.43 | 820.49 | 32.06 |
| 1500 | Sing direct/eligible download handoff | 455.37 | 37.10 | 393.79 | 47.82 |
| 9000 | Sing direct/eligible download handoff | 836.10 | 20.97 | 912.81 | 29.08 |

These are aggregate duplex MB/s, not download speeds. CPU includes the Go
process and HEV child; child accounting has OS clock-tick granularity. Small
CPU differences are not evidence of an Android battery advantage. At MTU9000,
native handoff and default HEV have essentially equal Vision throughput here;
HEV remains faster for the freedom workload. The MTU1500 results alone do not
establish that Sing is slower under its larger virtual-MTU configuration.

Sing's existing large-MTU support is separate from HEV's headerless local
TCP jumbo beyond the configured MTU. The audited sing-tun revision exposes no
independent switch for that HEV mechanism. This follow-up uses existing APIs;
it adds no local coalescing extension and does not enable virtio/GSO on Android's
plain descriptor. The reference
[sing-box Android default is 9000](https://github.com/SagerNet/sing-box/blob/v1.15.0-alpha.13/protocol/tun/inbound.go),
with a source comment about ENOBUFS on some devices at 65535.

The existing v2rayNG GUI MTU already feeds Android Builder, the SOCKS-backed
Sing controller and generated native sing-tun settings. Normal GUI changes
request a full VPN restart. Explicit custom inbounds continue to own their raw
MTU setting. This follow-up changes tests/documentation only; existing app
defaults and runtime dependency pins remain unchanged. Physical Android/ARM
throughput and energy measurements remain outstanding.

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
replace github.com/sagernet/sing-tun => github.com/Tozward/sing-tun v0.9.7-0.20261102125620-3855ec8dcf9c
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
[patch ledger](https://github.com/Tozward/sing-tun/blob/3855ec8dcf9cb1eb3036d334b1ecd5be89b14334/docs/xray-integration-patches.md).
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

## Production-test audit follow-up

The previous freedom/Vision columns do not isolate Vision's protocol overhead:
freedom uses a plain TCP echo, while Vision includes verified application TLS1.3
at both ends and an additional local Xray server/core and forwarding connection.
The new manual `freedom_tls13` control shares the exact application TLS fixture
with Vision; only Vision asserts its command-2 transitions. The original default
benchmark and its historical results retain their original workload definitions.
Whole-process CPU includes the application endpoints and simulated remote node;
it must not be presented as Android VPN-process CPU or battery use.

The re-audit reproduced and corrected two local integration boundaries:

- New upload handoff now rejects every TCP mask, including a fragment mask whose
  `Splice()` is true but whose later writes still require fragmentation. Unknown
  transports are also retained by the ordinary writer. Known protocol-ready
  TCP/TLS/REALITY/encryption/stats/Unix wrappers are checked without consuming
  stream data; existing raw-download unwrapping and Vision's original direct
  writer are unchanged. Actual fragment packets 2-20 and a transforming mask
  reproduce the bypass with the old implementation and pass after this guard.
- Dependency ST-API-004 fixes `CloseRead` while a directional upload remains
  backpressured after native TCP FIN/ACK completion. It cancels the owned upload
  and releases retained receive storage, including cancellation queued before
  the final ACK. Other dead connections, full Splice, CloseWrite and original
  socket ownership retain their prior behavior. The exact pinned dependency is
  `395f9425830a9991450bd0b26b54ecd5be80e647`.

### Matched TLS control results

[Run 41473742626](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41473742626)
verifies 9 cases / 27 uninstrumented rows and separate CPU diagnostics at source
`f4b170c30b4d8e7e0df04ff6794ceaca6d8cac12`. Production source is identical to
`f9a1f8e4a9cdf7dc0a939b7732f339550bc8e0cb`; the later commit only fixes exact
benchmark selection and validates every row's identity. Failed run 41472336035
is excluded: an unanchored `freedom` selector also matched `freedom_tls13`.

All controls use native bidirectional handoff + local jumbo, MTU 9000,
GOMAXPROCS=4, Go 1.27.3, one AMD EPYC 9V74 runner. The earlier complete matrix used
EPYC 7763; these absolute values must not be compared across runs as a code speedup.
Values are medians of three two-second samples. One-way operations transfer 4 MiB;
duplex transfers 4 MiB up and its 4 MiB echo, reporting aggregate throughput.

| Workload | Plain TCP MB/s | Direct application TLS1.3 MB/s | Vision with the same application TLS1.3 MB/s |
| --- | ---: | ---: | ---: |
| Upload | 1689.84 | 933.24 | 754.99 |
| Download | 2287.29 | 904.61 | 842.92 |
| Duplex | 1927.61 | 1328.02 | 1333.56 |

| Workload | Direct TLS CPU ms/op | Vision CPU ms/op |
| --- | ---: | ---: |
| Upload | 7.900 | 9.499 |
| Download | 7.731 | 8.193 |
| Duplex | 18.180 | 22.000 |

The TLS duplex throughput ranges overlap (1297.45–1332.00 and
1301.91–1334.02 MB/s); the 0.42% median difference establishes no advantage.
Vision still uses 21.0% more whole-process duplex CPU. Its matched one-way upload
and download are 19.1% and 6.8% slower. Thus the original plain-TCP/Vision gap is
not a measurement of native-integration loss, while Vision also is not cost-free.
CPU includes application endpoints and the simulated remote Xray node.

Every enabled native direction reports the entire bulk payload; TLS duplex
reports 4199936 raw bytes per direction per operation. No fallback or incomplete
handoff was observed. All cases emit a 53740-byte jumbo during the separate
warmup probe. Bulk VisionWriter/GoConn.Read client-copy stacks are absent from
the steady-state CPU samples. The remaining server upload path
`freedom -> CopyRawUplink -> buf.Copy -> writev` accounts for 5.84% of the Vision
duplex CPU samples. This is a separate server-side optimization candidate;
that cumulative sample share cannot predict a throughput improvement.

The production corrections retain original server forwarding and protocol
readiness. Further server splice/batching work requires its own controlled
experiment and framing, statistics and lifetime review. This audit does not
expand those upstream paths immediately before Android production testing.

## Follow-up: bounded socket read batches

[Run 41500278151](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41500278151)
compares 64/128/256KiB socket read limits at source
`20dbdaa46db10f46e63118f3b00c23878bb101c3`. An isolated copy of the pinned dependency
and alternate module file keep the module cache and production sources intact.
The only runtime difference between its three binaries is `goSpliceReadChunk`.
Source/binary hashes and every raw output are retained in the run's artifact.
Preparation-only failed runs 41499617699 and 41499964907 produced no measurements
and are excluded.

The experiment completes 195 samples on one Linux runner: five randomized
repetitions of nine bulk cases and four mixed-load cases for each batch size.
All cases use actual TUN MTU9000, GOMAXPROCS=4, Go1.27.3, an Intel Xeon Platinum
8573C runner and the preceding matched TLS fixtures. Absolute rates are not a
cross-version comparison with the earlier EPYC runners. Bulk cases assert
complete directional handoff and above-MTU output.
Mixed cases verify every connection's MTU/MSS, TLS1.3 and raw upload/download
warmup before measuring one or four bulk downloads beside a separate 256-byte
request/response connection for two seconds. Every flow must make progress and
its final payload must match. Setup and final worker joins remain outside timing.

The selected candidate is **128KiB**, retaining the existing TCP window,
transmit-capacity and shared-memory budgets. It does not wait for a full batch.
It can transiently reserve up to one additional 64KiB read chunk where the
existing budget permits. This applies to the library's directional and full
socket handoffs, including the SOCKS-backed Sing path; ordinary GoConn reads
and writes are unchanged.
Dependency commit `9af120bbf52457f6c946e4d63587c2bfed57e07e` records this as
ST-PERF-002, with upstream-first replacement criteria. The socket regression
distinguishes a real read above 64KiB from repeated small reads and checks a
32KiB capacity, backpressure, acknowledgement/resume, EOF and slab reclamation.

The table reports the median of five *paired percentage changes* against the
64KiB sample in the same repetition, rather than ratios of independent medians.
CPU includes application TLS endpoints and the local Vision server.

| 128KiB case | Throughput change | CPU change |
| --- | ---: | ---: |
| Plain TCP download | +9.93% | -6.11% |
| Plain TCP duplex | +7.38% | -6.49% |
| Vision download | +0.77% | -3.82% |
| Vision duplex | +0.38% | -1.49% |
| Four direct-TLS downloads with small requests | +7.53% | not measured |
| Four Vision downloads with small requests | +6.97% | not measured |

Plain download throughput and Vision download CPU improve in all five paired
samples. Both four-flow workloads improve throughput in all five samples; their
slowest-flow medians improve 7.44% and 6.52%, with Jain fairness at least 0.9997.
Single direct-TLS download throughput has a -2.47% paired median and +0.34% CPU;
single upload and TLS duplex gains are small and mixed. This is a workload-specific
batching tradeoff, not a uniform throughput or latency improvement.

Four-flow p99 request latency changes +0.34% (direct TLS) and +3.06% (Vision),
while p50 improves 5.53% and 5.00%. With one saturated Vision download, the
median observed worst scheduling gap increases from 3.511 to 4.514ms and fewer
probes complete. Ticker probes can drop ticks; latency percentiles describe
emitted requests and must be read alongside probe count and worst gap. Boundary
completion snapshots can include a small partial-interval effect. No Android
throughput, VPN-process CPU or battery saving is established by this Linux run.

256KiB increases some bulk rates further, but direct-TLS four-flow p95 latency
is worse in all five pairs (median +6.28%), and single-flow request p50 increases
in all five pairs for both TLS paths. It is not selected for the phone candidate.
The ordinary remote Vision server copier remains untouched: changing a local
fixture server would not accelerate an unchanged remote official Xray node.

This follow-up also fixes unsupported unconnected Unix datagrams at the native
handoff boundary. Their absent remote address now declines before touching the
native stream. Both directions reproduce the former panic and now preserve the
original descriptor and queued datagram. Connected datagrams still decline;
TCP/Unix streams and protocol readiness retain their preceding behavior.

### Candidate .4 validation

[Core run 41502724582](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41502724582)
at `d276f910aabb31c1303e56293ca108c17d9b9aa7` passes Linux and Windows default/
tagged checks, Linux real-TUN/Vision repeats and the complete 60-row baseline,
plus formatting/protobuf checks. Local macOS arm64 focused tagged race checks
pass using the final published dependency pin.

[Dependency run 41502596650](https://github.com/Tozward/sing-tun/actions/runs/41502596650)
at `9af120bbf52457f6c946e4d63587c2bfed57e07e` passes Linux focused races and
privileged descriptor/socket/kernel-memory-link checks, plus Windows compilation.
**Not run:** hosted macOS jobs in these workflows did not acquire runners and
were cancelled; GitHub reports arm64 capacity constraints. Local macOS memory-link
kernel cases require utun permission and were not run there; the corresponding
Linux privileged cases pass. The workflow totals must not be described as green.

[Android candidate run 41502856334](https://github.com/Tozward/v2rayNG-n/actions/runs/41502856334)
passes at app source `7f5ea105a4cadb51ff56871bcf27ed052c8a7b18`, version
`2.3.15.3-native-sing-tun.4` / code768: native adapter races/vet and FD repeats,
four-ABI combined AAR and signed release packages, both distributions' unit/
Kotlin/assembly/lint checks, and Android API24/API35 VPN backend TCP/UDP checks
at MTU1280/1500/9000. The arm64 Playstore APK is 32934142 bytes (612 bytes larger
than .3), SHA256 `029fc296c05ed591e0e84ac3b7edfc5ba4b8c205d88cd18d55ac4d1864afd5c8`.
No physical phone was operated, and no phone energy measurement was performed.
