# First-connection integration audit, 2026-11-03

The phone report concerns v2.3.15.4 / core e965fbf7, native Sing TUN,
MTU9000, TCP/REALITY Vision, testpre5, FakeDNS and route-only sniffing.
The app repository's `docs/first-connect-audit-20261103.md` records the matched
public-network experiment and its limits. Three interleaved cold starts plus
a 130-second idle comparison on the same phone found similar official/custom
HTTP-proxy timings. Those probes do not exercise native socket takeover and
do not establish the cause of the reported browser delay.

## Core-owned lifecycle fix

`Handler.Close` previously canceled its context, closed the stack, then waited
for all synchronous Xray dispatch calls before releasing the device. A VLESS
Process waiting for a stock preconnection can require its outbound Close to
release it. Core features can be registered with the inbound manager first;
blocking there prevents Core.Close from reaching that outbound. JSON config's
current outbound-first order does not make the protobuf/public inbound-removal
paths safe.

The native inbound now follows the existing inbound ownership contract: stop
admission, cancel its context, join the native stack's IO engines, close its
device. It does not wait for dispatcher code owned by a different feature.
Late TCP/UDP operations observe the closed native connection/device, never a
reused descriptor. The obsolete production WaitGroup and per-flow counter
operations are removed, including the same wait in benchmark cleanup.

`TestNativeCoreCloseWhileVLESSPreconnectPending` uses the real VLESS handler
with a gated dialer and verifies both feature orders. A second test leaves
foreign dispatch pending while eight concurrent Close calls release native
resources; late TCP/UDP link I/O fails, restart is rejected, and the foreign
owner can subsequently finish its own dispatch. Both regressions and the
complete native package pass local race checking.

## Small first-request regressions

A local REALITY decoy plus authenticated TLS1.3 application validates three
new connections, each exchanging 1, 37 and 9 bytes without a bulk warmup or
waiting for client EOF. It uses sniffing/route-only metadata like the phone.
The fixture waits for REALITY's *server-side* asynchronous decoy detection,
without warming its client or preconnections; otherwise that unrelated
fixture initialization introduces a five-second polling delay.

MemoryTun tests cover protocol/order behavior, but MemoryTun cannot accept
socket takeovers. Real Linux TUN tests therefore compare ordinary native
Read/Write against bidirectional handoff plus jumbo and assert both takeover
counters advance on every connection. Both TLS13 and REALITY outer transports,
with testpre0 and testpre5, are exercised separately. CI requires privileged
fixtures and runs the preconnect variant explicitly.

Stock VLESS preconnect Close/send has an existing race: Close closes preConns
while a background sender can send. This integration does not alter that
implementation. The testpre5 scenario runs without -race; testpre0 and the
native lifecycle/ownership regressions retain race checking. This is an
explicit test boundary, not a claim that the upstream preconnection race is
fixed. The non-race test still verifies exact first-response ordering.

Neither the close fix nor the app's backend-snapshot fix is established as the
reported first-page latency cause. No new tuning of upstream Vision,
preconnection, TCP engine, ACK/window or batching algorithms is included.

## UDP handshake feedback

The adapter previously ended an initial outbound failure with `onClose(nil)`
and did not call Sing's existing `HandshakeFailure`. A verified local Vision
fixture reproduces the UDP/443 rejection while MemoryTun observes no ICMP.
The same fixture with the existing Sing API as a positive control emits a
valid IPv4 or IPv6 unreachable quoting the original tuple. Successful UDP
flows also retained the initial snapshot until closure.

The integration now uses Xray's existing `session.TrackedConnectionError` to
report the original initial failure to the original native PacketConn. It
forwards any pre-existing error tracker after releasing its IO lock. The
first nonempty upstream response reports handshake success *before* local
delivery, matching Sing's establishment semantics; it frees the initial
snapshot and preserves the original packet batching. An existing write mutex
orders success against failure. No per-packet lock, copy or allocation is
added. Ordinary closure/cancellation does not synthesize an error; a live
flow's genuine outbound timeout still reports failure. Secondary ICMP-delivery
errors do not replace the original outbound error.

Regressions cover real Vision rejection and successful UDP, real DNS replies,
FakeDNS/NXDOMAIN with original-address quotes and same-tuple retries, IPv6
checksums, success/failure ordering, partially failed original batch writes,
empty responses, failed local writes, expired parent context, and reentrant
original trackers. Native TCP and Vision handoff code are unchanged.

### What the phone experiment does and does not prove

An unlocked foreground Edge refresh produced two sessions that sniffed
`www.google.com` and then logged the existing Vision UDP/443 rejection. The
user reported this refresh normal; an earlier 10:38 stall was reported before
a useful trace was available. These are not a reproduced before/after browser
latency experiment. An earlier synthetic Edge-UID test happened during
TOP_SLEEPING, with APP_BACKGROUND blocking, and no packet reached the TUN;
that result is excluded from awake-path diagnosis.

The real-TUN kernel regression explicitly opts its own sockets into
`IP_RECVERR`/`IPV6_RECVERR`. On the same phone, the released core with only the
test overlaid times out at 1.5 seconds in both families; the fixed adapter
delivers the unreachable in approximately 3–7 ms, three repetitions each.
The unmodified default UDP-read test times out for *both* old and fixed cores.
Linux treats this NoRoute indication as a soft error; error-queue receipt is
not automatically an immediate error for every client. See the
[Android UDP error delivery implementation](https://android.googlesource.com/kernel/common/+/b9d8a295ed6bc3cee846f8e3f27c9c6e9ebe43f2/net/ipv4/udp.c).

Chromium's standard QUIC socket configuration does not enable these error
options; Edge is a vendor fork. Therefore the corrected feedback is an
adapter-contract fix, **not proof of faster Edge fallback** or a complete
explanation of the first-page delay. No Sing error code, upstream Vision
policy, socket error subscription of other apps, or user flow setting is
changed. The original read-timeout evidence remains alongside the explicit
error-receiver evidence rather than being counted as a passing test.
