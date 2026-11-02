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
