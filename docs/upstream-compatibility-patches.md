# Upstream compatibility patches

Keep each correction separate from TUN APIs, dependency patches and performance
parameters. On upstream synchronization, prefer upstream's implementation after
the recorded regressions pass; remove the superseded local hunk and record its
replacement revision. Do not preserve a patch solely because it was once needed.

## XR-COMPAT-001 — incomplete plaintext TLS record classification

- Status: approved and applied on 2026-11-03. The user explicitly authorized
  this exception to avoiding upstream-internal changes:
  “允许合入这处修复并记录（推荐）”.
- Production location: `common/protocol/tls/sniff.go`, `SniffTLS`.
- Upstream reviewed: base7c8dbcb4 and main556767e4 retain the original behavior.
- Reproduction: a14459-byte ClientHello arrives as64 bytes, then its remainder.
  Sing can expose more TCP/read boundaries than the original TUN's queued
  multi-buffer reader. Returning ErrNoClue for each incomplete record consumes
  the dispatcher's two unknown-protocol attempts, losing the domain and its
  routing decision despite otherwise correct byte forwarding and preconnections.
- Correction: after recognizing the record header, return the existing
  ErrProtoNeedMoreData only while a declared plaintext record of at most16384
  bytes is incomplete. RFC8446 section5.1 and RFC5246 section6.2.1 establish
  that single-record bound. Larger incomplete declarations keep ErrNoClue.
  Complete records, fewer-than-five-byte prefixes and non-TLS retain their
  existing classifications. There is no new TLS parser, buffer, timer, goroutine
  or transport parameter in this patch.
- Scope: shared TCP sniffing in ordinary and native builds, not only Sing TUN.
  QUIC's separate ReadClientHello caller is unchanged. It does not reassemble a
  ClientHello split across multiple distinct TLS records.
- Bounds: a newly awaited record fits within16389 bytes including its header,
  below the existing32767-byte observation window. The correction does not
  create a global cache-size limit or absolute200ms deadline. Existing read-time
  budgeting, metadata fallback, invalid-SNI behavior and reader batch sizes
  remain in force. Legitimate additional fragments require additional existing
  read/timer work; zero performance cost is not claimed.
- Regressions: `TestFragmentedTLSNeedsMoreData` (short prefixes, every incomplete
  prefix of a valid record, exact16384/oversize bounds, complete and invalid
  records); `TestFragmentedTLSReadBudgetAndMalformedInput` (finite continuous
  oversized input, legal maximum malformed body, EOF, stall and cancellation);
  `TestFragmentedTLSWithSmallReads` (real Go ClientHello,32/128-byte chunks after
  the full record header, actual TimeoutWrapperReader); and mandatory privileged
  `TestNativeKernelLargeClientHelloDomainRoute` (verified TLS through a domain
  rule with rejecting fallback, original stack and actual native handoffs).
- Cancellation evidence: the malformed-input test's context-aware test reader
  is not a timing guarantee for real TUN cancellation. Native close/late-IO and
  half-close tests remain required separately.
- Prior evidence:20 strict phone repetitions of the final bounded overlay
  passed160 connections. See `preconnect-latency-study-20261103.md` for the
  failed adapter-only alternatives and the rejected unbounded one-line variant.
- Retirement: test an equivalent upstream classification/reassembly solution
  against these protocol, routing, resource-bound and cancellation regressions.
  Adopt it when equivalent; record the upstream revision and remove only this
  production hunk. Do not retain both implementations or tune NoClue retry
  counts to hide a regression.

The dependency's separate ST-FD/ST-API/ST-PERF ledger remains owned by the
sing-tun fork. XR-COMPAT-001 introduces no new dependency patch.

### Validation gate refinement

The first Linux CI run41662649266 exposed a race on the unchanged Vision
NumberOfPacketToFilter field in the synthetic node's two forwarding tasks:
XtlsFilterTls writes while VisionReader reads. These accesses match upstream7c;
the bounded TLS classification does not modify that state. The initial failing
job is retained as evidence and is not reported as a passing race check.

The mandatory domain-routing race regression now uses verified inner TLS over
the direct outbound, retaining the same fragmented ClientHello, rejecting
fallback, original-stack control and actual native bidirectional handoffs.
The additional TestVisionKernelLargeClientHelloDomainRoute runs the genuine
Vision path in the separately mandatory non-race protocol step alongside the
existing stock-preconnect controls. Existing adapter, cache, ownership and
native IO race tests remain enabled. This boundary does not certify upstream
Vision filter state as race-free and does not introduce a production workaround.
