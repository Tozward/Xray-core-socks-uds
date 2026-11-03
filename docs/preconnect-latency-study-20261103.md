# Preconnection behavior and TUN integration, 2026-11-03

The study sections below preserve the original research snapshot. The approved
integration and its active patch record are appended at the end.

## Scope and release boundary

This is a synthetic, phone-local behavioral investigation of application
v2.3.15.5 / core93cbbf3e / Sing2c2f8b28. The installed application, selected
node, VPN service, DNS, per-app policy and security settings are unchanged.
No production source or module pin is modified by this research branch.
The Sing dependency working tree is also unchanged.

The TLS compatibility proposal below is **not applied**. The user previously
required avoiding upstream-internal changes; an explicit exception is pending.
Do not mistake passing overlay experiments for an approved production patch.
The formal v2.3.15.5 release remains the previously validated signed binary.

## Source comparison with Xray's own TUN

The upstream base is 7c8dbcb4. Its TCP stack and TCP connection code match
the tested source. The official-stack control uses that TCP stack plus the
current shared handler and borrowed-descriptor adapter, not an independently
compiled official application.

Both upstream TUN and Sing enter Xray after the application-side TCP
handshake. Upstream sends SYN-ACK and dispatches on the valid final ACK.
Sing's handshake notification waits for establishment before our adapter calls
the shared TUN handler. Neither has a special early-preconnection shortcut.
Both then use TimeoutWrapperReader, dispatcher sniffing/routing, and the same
VLESS Process. The original preconnection pool, expiry, replenishment, dialer
and Vision readiness rules remain unchanged.

The shared preconnection implementation lazily starts five workers. Cold
requests still pay initial dialing; warm, unexpired offered connections avoid
that dialing. Long-idle expiration, pool-exhausting bursts and original
Vision UDP443 rejection remain distinct scenarios, not proven causes of the
user's intermittent browser delay.

## Experiment and phase definitions

The Xiaomi 14 Pro runs a separate static Linux/arm64 test binary. It creates
only disposable TUN prefixes; temporary priority9998 rules select those
prefixes for UID0 only and are removed by a trap. No default route, DNS,
physical interface, power policy, personal proxy configuration, browser data
or application package is changed. Both tested TUN paths actually transfer
through the Linux kernel, with MTU9000. HEV is the APK-pinned library.

A local authenticated Vision node and verified inner TLS1.3 echo application
are connected through a transparent loopback relay. Only each outer
connection's first server flight is delayed150ms; later application data is
not delayed. TLS1.3 and REALITY are tested separately. Each case has one cold
connection and three independent warm connections, repeated three times.
Before warm testpre5 requests, all five new workers must be observed offering
fully dialed connections on their unbuffered channel; a fixed sleep is not
used as proof that a pool is ready. Testpre5 remains non-race opt-in because
the stock Close/send competition is separately recorded, not repaired here.

Four paths are compared: original Xray TCP stack, Sing ordinary Read/Write,
Sing production bidirectional handoff plus jumbo, and HEV Android defaults.
Actual upload/download handoff counters advance on every bidirectional sample.
Normal and large-fragmented ClientHello cases make384 measured connections
in total, each with three small request/response exchanges before EOF.

The `routed` event is immediately before outbound dispatch; the VLESS
`outbound_connection_obtained` event follows pool acquisition or dialing.
Their difference therefore isolates that phase in this fixture. The
`xray_inbound` event has different semantics across paths: TUN handler entry
for the two native stacks, but decoded SOCKS CONNECT for HEV. It is not a
uniform socket-accept timestamp. Logs contain synthetic endpoints only.

## Observed preconnection benefit

Warm normal-ClientHello medians, milliseconds; nine samples per cell:

| Outer | Path | testpre0 dispatch-to-connection | testpre5 dispatch-to-connection |
| --- | --- | ---: | ---: |
| TLS1.3 | Xray TCP stack | 166.205 | 0.099 |
| TLS1.3 | Sing ordinary IO | 167.919 | 0.079 |
| TLS1.3 | Sing native handoff | 161.104 | 0.063 |
| TLS1.3 | HEV defaults | 165.182 | 0.173 |
| REALITY | Xray TCP stack | 165.882 | 0.118 |
| REALITY | Sing ordinary IO | 165.452 | 0.125 |
| REALITY | Sing native handoff | 166.091 | 0.153 |
| REALITY | HEV defaults | 176.062 | 0.164 |

This establishes that a ready preconnection avoids the controlled outer
handshake delay through the actual Sing integration. It is stronger evidence
than checking a parameter or counting sockets. These are not public-site
latencies, universal performance equivalence, whole-browser measurements,
throughput tests or battery-energy results. Ordering and phone scheduling
also prevent treating small cross-path differences as a universal winner.

## Confirmed TLS-fragment compatibility difference

The large synthetic ClientHello is14459 bytes: first64 bytes, then the rest
after25ms. The original Xray reader can hand multiple queued buffers to the
sniffer at once. Sing's ordinary net.Conn reader can expose more individual
chunks. SniffTLS classifies a recognized but incomplete TLS record as
ErrNoClue; dispatcher stops after two such attempts.

In both transport matrices, all official-stack and HEV large cases sniffed
the domain, while both Sing paths did not. Success of byte forwarding had
hidden this routing difference. A strict domain rule with a rejecting default
outbound makes the old Sing case fail and the Xray-stack case pass.
This is an interaction between read boundaries and the existing sniffer
contract, not evidence that the preconnection pool itself is disabled.

Two adapter-only drafts were rejected and removed:

- A larger contiguous read still returned the first8948-byte TCP segment and
  did not reliably collect the remaining segment. Passing oversized buffers
  into Vision would also violate its buf.Size block-size assumption; simply
  enlarging a buffer is not a safe fix.
- A read-only queued-byte API plus bounded draining improved the strict case
  but passed only11/12 requests in the sampled run. The next segment can still
  be unprocessed. No sleep, scheduler yield or new TLS parser was added to make
  that timing-dependent approach appear reliable. The prototype API was moved
  out of the dependency working tree.

The reviewable proposal in `proposals/tls-record-fragment.patch` changes
classification to ErrProtoNeedMoreData only for an incomplete plaintext TLS
record whose declared length is at most16384 bytes, per RFC8446 section5.1.
Longer declarations preserve the original early-exit classification. This
retains the existing read-time budget rather than adding buffering or tuning
the TUN/transport engines. It does not reassemble ClientHello across distinct
TLS records. Newly recognized TLS-like prefixes may use more of the existing
budget; this behavior change is explicit, not described as risk-free.

The unbounded one-line variant was rejected: a finite synthetic oversized
stream accumulated253957 cached bytes in33 reads. The bounded proposal exits
such cases in two reads with8197 cached bytes in the same fixture. Legal
maximum malformed records, EOF, stall and cancellation also terminate; the
stall measured about201ms and cancellation about21ms. The existing budget
accounts for cache-read time, so it is not an absolute200ms wall-clock limit.

Both unbounded and final bounded proposals passed20 strict phone repetitions
each:80 connections per path,160 total per proposal. The final proposal also
passes200 incomplete-prefix checks, oversized-declaration controls and
race-enabled TLS/dispatcher/proxy/native regression suites in an overlay.
The installed VPN service continues running unchanged; overlay binaries are
separate test processes.

If the exception is approved, keep this compatibility correction separate
from TUN APIs and performance parameters. On upstream sync, prefer an upstream
fix once these fragmented-read, strict-routing, invalid-length and cancellation
regressions pass; record the replacement revision and retire the local hunk.
Current upstream556767e4 still has the original classification.

## HEV handshake control

The default HEV matrix additionally showed about200–214ms between writing
the inner ClientHello and decoded SOCKS CONNECT, before sniffing or pool
acquisition. Its standard negotiation sends authentication methods with
MSG_MORE and waits for a reply; pipeline is omitted in both the existing APK
configuration and the benchmark. The library's existing pipeline option was
enabled only in a separate synthetic child process as a positive control.

In that control, the median corresponding phase fell to about2.5–2.7ms,
and warm testpre5 first-response median fell from271.313ms to54.664ms for
this TLS fixture. This supports a local negotiation/corking cause; it is not
a claim that the Sing engine is universally faster. The APK's HEV settings
and library are unchanged, and authenticated/custom SOCKS compatibility would
need separate verification before proposing an application change.

## Evidence and reproducibility

The opt-in `TestNativeKernelPreconnectLatencyStudy` contains the matched
fixture, worker-readiness observation and per-phase JSON samples.
`TestNativeKernelLargeClientHelloDomainRoute` is also opt-in: it deliberately
reproduces the unresolved baseline failure until an approved patch is applied.
The HEV helper's default is unchanged; XRAY_HEV_PIPELINE_CONTROL enables only
the explicitly labeled experimental control.

Local evidence is kept under the workspace's
`artifacts/native-sing-tun/preconnect-study-20261103/`, including unchanged
baseline TLS/REALITY matrices, failed adapter drafts, bounded/unbounded
proposal logs, safety controls, scripts and overlay sources. These artifacts
contain no personal node credentials or browser content. The diagnostic code
and documentation add no code, timer, logger or allocation to the APK.

## Approved integration

The user subsequently authorized the bounded TLS compatibility correction.
It is now applied to SniffTLS, with protocol and dispatcher regressions in the
ordinary/native CI suites. The strict real-TUN domain-routing regression is
mandatory rather than opt-in; the larger timing matrix remains opt-in.

`upstream-compatibility-patches.md`, XR-COMPAT-001, records the exact scope,
resource bounds, remaining limitations and upstream-first retirement condition.
The Sing dependency and all discarded adapter/buffer prototypes remain unchanged.
The proposal patch is retained only as historical review material; executable
source and tests are authoritative after this integration.
