> **Historical document.** This report reflects the codebase as of its original date and has been
> superseded by [`PRODUCTION-READINESS-AUDIT.md`](./PRODUCTION-READINESS-AUDIT.md), which is the
> authoritative readiness report. Findings here may already be fixed; do not use this file to make
> current readiness decisions.

# Threat Intelligence Ecosystem Audit

> Follow-up: [Current ecosystem audit and implemented fixes](ECOSYSTEM-AUDIT-2026-10-21.md) records subsequent code changes, live provider probes, and current verification. Outstanding items below are historical where the follow-up marks them fixed.

**Reviewed:** 21 October 2026  
**Scope:** feed adapters and seed configuration, ingestion/normalization, inventory correlation, delivery/outbox, CVE deduplication. This is a code and configuration audit; it does not claim that public providers were reachable from the deployment or that tenant-specific inventory is complete.

## Executive assessment

The system has a solid base: outbound feed requests use an allowlist, DNS resolution rejects non-public addresses and pins the validated address for TLS; ingestion is bounded and concurrent; PostgreSQL outbox writes are durable and idempotent per advisory/recipient; CVE finding IDs survive re-evaluation; and dispatch rechecks current inventory before transport.

The main risks were data-contract drift in the starter feeds, false applicability from ignoring NVD's per-CPE ranges, dropping unscored vulnerabilities, a feed circuit breaker that never recovered, stale pagination ETags, and mixed-validity advisories reaching email. Fixes for those issues are applied in this release. The remaining largest ecosystem gaps are FIRST EPSS being fetched as a bulk API mirror, no source-specific vendor PSIRT/CSAF adapters, no live endpoint telemetry beyond the product watchlist, unbounded CVE history/whole-corpus matching cost, and notification routing/digest settings that are declared but unused.

## Feed assessment

| Source                           | Quality and relevance                                                                                                       | Reliability/coverage observations                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NVD CVE API 2.0                  | Broad canonical CVE, CVSS, references and CPE applicability data; the primary general vulnerability source.                 | Correct API family and bounded modified-date polling are configured. The seed previously contained a fake API key. The production seed now uses unauthenticated access at a conservative rate; operators can configure a real key. Missing CVSS records are retained with explicit `UNKNOWN` severity. Each configured CPE range is now evaluated independently.                                                                                                              |
| CISA KEV                         | High-value, focused signal for vulnerabilities known to be exploited; useful for prioritization rather than broad coverage. | The adapter validates the catalog and enriches cached CVEs, but KEV entries do not independently create rich CVE/product records. A CVE absent from the NVD cache cannot yet match inventory from KEV data alone. CISA describes KEV as an authoritative exploited-vulnerability catalog and recommends its use in prioritization. [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)                                                                   |
| FIRST EPSS                       | Useful, independent probability/ranking signal; complementary to CVSS and observed exploitation.                            | The adapter pages through the public API's entire dataset (up to 500,000 rows) on each run. FIRST says this API is for one or a small batch of CVEs and recommends the daily CSV/GitHub dataset for bulk synchronization. This is a material bandwidth and latency bottleneck and should be changed to target-CVE lookup or a bounded daily bulk-file adapter. [EPSS data guidance](https://www.first.org/epss/data.html), [EPSS API parameters](https://api.first.org/epss/) |
| Microsoft MSRC starter entry     | Potentially valuable vendor-specific remediation/impact context.                                                            | The configured CVRF `updates` endpoint is not the normalized-CVE array expected by `JSON_SEARCH_API`, and the fixture contained a fake credential. It is disabled by the seed until a source-specific CVRF adapter and schema tests exist.                                                                                                                                                                                                                                    |
| Palo Alto Networks starter entry | Valuable vendor PSIRT applicability and product-specific version guidance.                                                  | The configured URL is not the stable JSON path and its advisory response is not a normalized-CVE array. PANW documents a stable `/json` rendering and marks the separate API as beta. It is disabled by the seed until a source-specific adapter exists. [PANW Security Advisory API](https://security.paloaltonetworks.com/api)                                                                                                                                              |

NVD and CISA are authoritative primary sources; EPSS is a distinct predictive signal. Current source diversity is therefore good for general CVE, observed exploitation, and probability, but weak for vendor-specific corrections and affected/fixed product statements. NVD identifies its 2.0 APIs as the preferred way to keep current and recommends changed-date retrieval; the implementation follows that API family. [NVD API/data guidance](https://nvd.nist.gov/vuln/data-feeds) The current allowlist, TLS validation, and outbound reachability still need deployment-level checks.

## Pipeline and normalization

Ingestion runs enabled feeds concurrently with a maximum of six workers, pages NVD/EPSS, bounds response bodies and page/result counts, rejects invalid JSON/schema, and writes changes in a transaction. The key bottlenecks are long NVD windows (up to 50,000 records), repeated full EPSS retrieval, serial per-page throttling, and a complete cached-CVE/inventory correlation after every run. The CVE cache has no retention or partition strategy, so runtime and memory use grow over time. `putMany` is a single SQL statement; very large result sets can exceed PostgreSQL's bind parameter limit unless writes are chunked.

Fixed in this audit:

- Removed the unsafe feed-level `If-None-Match` reuse for NVD/EPSS paginated queries. Those URLs vary by page or time window, so a single ETag could incorrectly treat a partial response as a complete unchanged feed. Static catalog/generic endpoints retain conditional requests.
- Added a bounded circuit-breaker cooldown with a half-open recovery probe. Five failures no longer make a source permanently unpollable; a successful probe clears its failure count and open time.
- Reconcile complete CISA KEV and EPSS snapshots as authoritative current enrichment, clearing cached flags/scores when an item disappears instead of retaining stale risk indefinitely.
- Seed configuration now enables only implemented, schema-compatible sources and contains no placeholder API credentials. Existing legacy MSRC/Palo Alto seed rows are disabled during reseeding.
- Changing a feed URL, adapter, or authentication type clears its ETag and circuit state. Selecting `NONE` clears any stored credential.
- Retained valid NVD CVEs without CVSS metrics using `UNKNOWN` rather than dropping them or fabricating a low score.

## Matching against internal telemetry

Correlation currently uses the operator-managed watchlist's CPEs/PURLs, vendor/product aliases, and a conservative title/description fallback. It does not ingest EDR/CMDB/cloud inventory events or validate installed software from live endpoints. Inventory freshness and version accuracy remain operator-dependent.

Fixed in this audit: NVD stores version bounds on individual CPE match criteria. Correlation previously flattened those criteria and ignored their individual ranges; it now evaluates each criterion with its own interval. Existing safeguards retain uncertain version/architecture cases for review, keep explicit version exclusions authoritative, and preserve finding identity on re-evaluation. Unscored CVEs are no longer silently lost.

Residual accuracy limits: NVD AND/negated applicability is flagged for review rather than fully evaluated; nonstandard vendor version ordering remains review-only; fallback text matching is review-only; and source authority precedence is configured but not applied as a deterministic per-field merge policy. Duplicate CVEs with equal modification timestamps can still resolve by feed arrival order. Matching cost is roughly proportional to cached CVEs × active assets × candidate CPEs, with no asset/CVE indexing.

## Notification and email

The transactional outbox deduplicates by dispatch key, channel and target, claims work with `SKIP LOCKED`, rechecks recipient/hook state, retries transient failures with bounded exponential delay, and records provider acceptance separately from inbox delivery. SMTP uses bounded TLS settings; webhooks are signed and carry an idempotency key. There is no claim of inbox delivery.

Fixed in this audit: if any finding in a queued advisory has become stale, the entire pre-rendered payload is rejected before transport. Previously, a partially stale bundle could still send the stale finding because only the all-stale case failed.

Remaining alert-quality risks: one advisory can aggregate findings across unrelated owner groups and is sent to every recipient whose severity tier matches; there is no owner-group routing or per-asset authorization. The `digestBatchingEnabled` and `digestWindowMinutes` settings are not consumed by the worker, so batching is not implemented despite being represented in settings. Plain-text delivery contains less context than the rendered advisory, and transient/provider acceptance does not prove delivery. Reconcile provider receipts after a crash between remote acceptance and local commit to limit duplicate mail.

## Deduplication and integrity

CVE identifiers are trimmed and uppercased; duplicate records within an ingest run prefer the newest modification timestamp; findings are keyed by canonical CVE plus asset ID; and the outbox unique key prevents duplicate enqueue for the same dispatch target. Reconciliation keeps stable finding IDs and operator lifecycle decisions. This controls common CVE-level alert duplication but does not provide a general indicator store: hashes, domains, IPs, URLs, aliases, and campaign indicators are not ingested or deduplicated. The standalone `InRunDeduplicator` helper is not used by the main engine.

Remaining integrity/performance work: canonicalize all persisted CVE record keys at ingestion, define deterministic tie-breaking/field authority across sources, chunk bulk upserts below database parameter limits, and introduce an approved retention/archive policy for CVE history, outbox, and audit data.

## Recommended next work

1. Replace EPSS full-dataset API polling with matched-CVE batches or a bounded daily bulk-file adapter, including source freshness and partial-import checks.
2. Add supported, versioned MSRC CVRF and PANW/CSAF adapters, preserving affected/unaffected product statements and vendor remediation links; do not represent arbitrary vendor endpoints as normalized JSON.
3. Add inventory synchronization from CMDB/cloud/endpoint systems with observed-at timestamps, software identifiers, and stale-asset alerts.
4. Implement recipient/owner-group routing and digest batching; test that a finding is disclosed only to authorized recipients and that urgent KEV/critical events bypass digest windows.
5. Add indexed candidate generation and chunked persistence; benchmark realistic corpus/inventory sizes and record per-feed request/page latency, cache age, correlation counts, and alert precision/false-positive feedback.
6. Define retention, archival, backup restoration, and external immutable audit-export policies with operational owners.

## Verification

Code-level tests cover range-aware matching, unknown CVSS retention, pagination ETag behavior, feed cooldown/recovery, bundle staleness, and existing PostgreSQL lifecycle/delivery behavior. The test suite uses mocked provider responses; live provider schema compatibility, DNS/TLS availability, SMTP deliverability, alert precision on real inventory, and production-scale latency remain deployment acceptance tests.
