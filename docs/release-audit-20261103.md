# Native TUN release audit, 2026-11-03

## Scope and architecture

The reviewed Xray changes are relative to `7c8dbcb4bbec7f80d16070069e0b2f7bf3aca62c`;
the separate dependency changes are relative to sing-tun
`611d83b7a57b4719be45581eb674942ff561de6c`. This includes the fork's existing
SOCKS-over-Unix-stream protocol, not only the new native inbound. Unrelated
official protocol implementations are not rewritten.

The native inbound remains an adapter to the existing dispatcher and TUN flow
handler. It does not embed sing-box, duplicate routing, replace DNS/FakeDNS or
introduce a second Android TUN reader. Vision retains authority over padding,
TLS input and each direction's protocol readiness. Native socket handoff is
conditional; masks, unknown wrappers, cached/timed reads and multiple outbounds
retain ordinary forwarding. The original kernel-splice path is preserved.

Buffer and descriptor ownership were reviewed through success, partial writes,
backpressure, EOF, half-close, cancellation, setup failure and engine exit.
No additional confirmed native-path defect requiring an architecture rewrite
was found. This is an audit result, not a proof that every possible defect is absent.
The data path still needs TCP retransmission storage and kernel/user boundaries;
removing local SOCKS does not establish end-to-end zero-copy or a battery claim.

## Corrections

| Area | Evidence and correction | Regression owner |
| --- | --- | --- |
| SOCKS UDS negotiation | Select no-auth only when offered by the client. This is protocol negotiation, not a claim that this no-auth-only protocol supported password authentication. | `proxy/socks_uds/server_test.go` |
| SOCKS UDS lifetime | Apply existing level-0 handshake policy, clear its deadline after the handshake, close on context cancellation, and join/interupt association links on shutdown. | `proxy/socks_uds/server_test.go`, `udp_test.go` |
| SOCKS UDS packets | Forward final payload returned together with EOF, keep payload ownership single, and discard an oversized 16-bit response frame without corrupting the next packet. | `proxy/socks_uds/udp_test.go` |
| Dependency structure | ST-API-002 already implements public `SpliceDownload`; remove the unreachable former ST-API-001 internal implementation. Preserve full/directional reservations and public APIs. | dependency patch ledger, full/directional race cases |

The old SOCKS implementation reproduces these failures in an overlay; fixed
focused tests and repeated races pass locally. The dependency cleanup leaves
the selected 128KiB limit, windows, storage budgets and local-jumbo conditions
unchanged. Its final pin is `2c2f8b289bf652b432506e0a6fe50e6ac6bd1fa2`.

## Upstream synchronization

Keep `docs/xray-integration-patches.md` in the dependency fork as the individual
ST-FD/ST-API/ST-PERF patch ledger. Prefer equivalent upstream fixes, carry their
regressions, and retire only the replaced local hunk. The reviewed upstream dev
head `5b0a1a7a394ed49d1a1adab3877284b86a8af94e` adds routed-port support and does
not replace these lifecycle/handoff fixes; it is not merged for this release.

The intentional Xray integration points are the optional inbound registration,
existing TUN flow admission, dispatcher buffer/statistic wrappers, and the two
protocol-ready freedom/VLESS upload and download copier boundaries. Future
changes to Vision framing, mask contracts, socket wrappers or stat writers need
the corresponding handoff regressions, not a blind reapplication of these hunks.
SOCKS UDS is a separate custom protocol; its fixes must not be pasted into the
official SOCKS implementation without reviewing that different ownership model.

Default core builds remain independent of optional GPL SagerNet dependencies.
Standalone native builds explicitly use `with_sing_tun`, have separate archive
names, include complete GPL and component notices, and record pinned source,
module checksums and build flags. The ordinary release workflows exclude the
custom `-native-tun.` release tags to prevent default and native assets mixing.
Windows native device support is not added or claimed by this release.

## Physical-device method and limits

Root ADB remains available with Xiaomi 14 Pro / Android16 locked and dozing.
Core fixtures use only disposable TUN links, synthetic addresses, loopback
servers and test certificates. Android needs a UID0-only policy for those test
prefixes and an explicit IPv6 prefix route on each disposable interface; no
default route, physical interface, personal node or system DNS is changed.
The policy is removed in `finally`; interface-owned routes disappear on close.

The preceding candidate's IPv4/IPv6 native transfers, independent EOF/half-close
and real Vision readiness/handoff pass three repetitions after that fixture
adaptation. Preparation failures caused by missing Android test routing are not
counted as product failures or successful measurements. Release-pin CI and
physical results are recorded separately when complete.

The phone is charging. PowerStats/rail availability must be established before
claiming electrical energy; CPU time or throughput alone is not battery usage.
Application tests use a separate audit application ID and synthetic storage,
with VPN traffic limited to shell UID. They do not inspect personal application
databases, subscriptions, node credentials or global user traffic histories.

## Release-pin evidence

The Android runtime pin is `e965fbf73b280483598d7d2ad4b406c00464fcbc`;
standalone archives use `0ada464dd11167cbc36ffc4db210fa3bccd91c0f`.
The intervening changes contain packaging/notices/docs and one test-format fix;
all production Go files, `go.mod` and `go.sum` are identical. Native archives
from [Actions 41523039867](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41523039867)
have clean source provenance, three matching SHA256SUMS, complete GPL text and
component notices. Darwin arm64 and Linux arm64 executables pass startup/version checks.

[Final core verification](https://github.com/Tozward/Xray-core-socks-uds/actions/runs/41522989485)
passes Linux, Windows and formatting, including ordinary builds without optional
SagerNet packages, tagged races, Linux privileged descriptors/Vision and all
60 measured CI baseline rows. Hosted macOS never acquired a runner: its annotation
reports capacity exhaustion, not a test assertion. The equivalent seven-package
macOS arm64 race suite passes locally. The separate dependency's
[three-platform run](https://github.com/Tozward/sing-tun/actions/runs/41512120906)
passes. This does not turn unexecuted real-utun or Wintun cases into runtime evidence.

On the locked Xiaomi 14 Pro / Android16 kernel, release-pin native IPv4/IPv6
transfers, download EOF with continued upload, and real Vision-ready socket
handoff pass three repetitions. Only synthetic local addresses and local TLS
fixtures are used. UID0-only test policies and every disposable TUN are removed.

### Physical-kernel matched measurements

These are static Linux arm64 Go test executables on the Android kernel, not APK-only
or external-network throughput. Actual TUN MTU is 9000, HEV is the exact Android
library included in the APK, and native raw byte counters/jumbo packets are checked.
The HEV shared library SHA matches the final AAR-input artifact. Each cell is the
median of three uninstrumented 2-second measurements; retain every original sample.
CPU includes the Go application/server/Xray/local node and the HEV child.

| Go P budget | Transport | HEV aggregate MB/s | Native aggregate MB/s | HEV CPU ms/8MiB | Native CPU ms/8MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| 4 | freedom | 395.74 | 721.96 | 33.18 | 13.68 |
| 4 | freedom_tls13 | 509.84 | 552.45 | 33.31 | 23.26 |
| 4 | vision_tls13 | 575.61 | 500.48 | 34.48 | 26.52 |
| 8 | freedom | 129.90 | 557.87 | 71.74 | 17.89 |
| 8 | freedom_tls13 | 126.77 | 497.65 | 77.83 | 27.04 |
| 8 | vision_tls13 | 120.10 | 445.33 | 85.32 | 31.07 |

Duplex counts both directions (8MiB/op); each one-way operation counts 4MiB and
uses a request/completion protocol. The latter is a stop-and-wait transaction,
not a continuous-flow bandwidth ceiling. HEV's default 64KiB ring, Nagle/ACK/window
behavior and small control messages can affect its tail; no packet trace establishes
one specific cause. Do not compare aggregate duplex MB/s directly to one-way MB/s
or advertise the low one-way HEV result as its general speed limit.

P budgets limit the entire Go fixture while the HEV C worker is outside that Go
limit. Fixed case order, heterogeneous CPUs, scheduling and frequency are not
controlled. The P8 run is an additional sensitivity test, not a replacement for P4
or a basis for combining scores. P4 Vision duplex is approximately 13% slower on
the native path while using approximately 23% less CPU time per 8MiB; retain this
tradeoff. The substantial P8 shift further prevents a universal speed ranking.
None of these CPU metrics is an electrical-energy measurement.

Full local logs and JSON summaries are under workspace
`artifacts/native-sing-tun/final-release/phone/` (`core-final-kernel.txt`,
`core-final-matched-benchmark.txt`, `core-final-matched-p8-duplex.txt`, and their
summaries/route-cleanup records). The phone is charging; Android reports zero
supported hardware power monitors. No governor/thermal policy, global battery
statistics, private profile database or personal traffic history was modified/read.

### Known-vulnerability checks

`govulncheck` v1.9.0 with Go1.27.3 reports no reachable known vulnerable symbol
or imported affected package for the native core's Darwin/Linux source entries
or the combined AAR's host source entries. The actual Android arm64 c-shared
binary has the pinned core/dependency and correct `with_sing_tun` build tag.
Stripped binary scans fall back to module-level precision and report
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for the unmaintained OpenPGP
packages in `x/crypto`. Those packages are absent from the Linux core and actual
Android AAR import graphs; preserve the raw warning and this interpretation.
A direct Android source symbol scan was not run locally because its NDK/cgo
asset setup is unavailable. Known-vulnerability scanning does not replace the
manual review of this fork's code.
