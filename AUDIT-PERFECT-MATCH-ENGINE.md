# VulnStream Enterprise Perfect-Match Engine — Adversarial Architecture Audit

**Scope:** pre-CVE correlation, matching math, alias resolution, range logic, and the fixes applied in this pass.
**Verification:** all suite runs were executed against a **real PostgreSQL 16 instance** (throwaway cluster), not a skipped path.

| Run | Result |
|---|---|
| `npm run test` (`TEST_DATABASE_URL` set) | **270 pass / 0 fail / 0 skipped** |
| clean-HEAD baseline (`git stash`, DB set) | 265 pass / 3 fail / 10 skipped |
| `npm run lint` | 10 pre-existing `TS2393`, **zero introduced** |
| `npx tsx server/migrate.ts` on empty DB | 22/22 migrations applied |
| `version_satisfies()` verdict matrix | 7/7 correct (incl. distro suffix, prerelease, integer and single-bound → `REVIEW`) |

The three failures that remained at the end of the previous pass have been fixed (§4). Two were stale test expectations, one was a real authorization defect. All 270 tests now execute against a live database — nothing is skipped.

**This pass found that the correlation pipeline had never worked end to end.** Details in §3.

---

### 1. Zero-Day Analytics & Early-Stage Matching Blind Spots (No Published CVE)

#### 1.1 The Pre-CVE Correlation Gap — findings and fix

**Observed failure (pre-fix).** The system had **no durable identity for an unpublished vulnerability**. Two independent mechanisms both treated each article as its own incident:

- `server/correlation/ingest.ts` deduplicates only on `sha256(url|title)` — a Reuters and a BleepingComputer story about the *same* zero-day are two rows, two match sets, two alert streams.
- `src/utils/intelligenceMatcher.ts` keys matches on `quickHash(`${cveId || article.id}:${asset.id}`)` — with `cveId = null` the key degenerates to the article hash, so every paraphrased article re-keys the same asset.

**Data-flapping / duplicate-alert loop on publication.** When NVD publishes the CVE weeks later, the canonical pipeline generates fresh findings for `CVE-…` while the pre-CVE review items are still open. Consequences observed in the code paths:

1. **Double notification** — the zero-day digest path (`pipelineEngine.rankAndRateLimitZeroDays`) and the canonical finding path fire for the same incident.
2. **Review bypass** — an operator's `FALSE_POSITIVE`/`NOT_APPLICABLE` decision on the pre-CVE item is keyed by the *article*, not the vulnerability; the new CVE finding is not suppressed. `intelligenceMatcher.ts` guards `RESOLVED`/`FALSE_POSITIVE` findings, but only findings that were ever bound to that CVE ID.
3. **Adversarial window** — an attacker who controls an alternative feed can seed a pre-CVE narrative ("Cisco IOS XE zero-day, actively exploited") that *nothing* reconciles later; the poisoned match persists indefinitely as open review noise, or worse, is corroborated by a second planted article and promoted through the `zeroDay` density gate (`signals >= 2 && density >= 0.002` — trivially satisfied by a 200-word planted article with four keywords).

**Fix applied (enterprise grade).**

- **`server/migrations/018_pre_cve_clusters.sql`** — new `pre_cve_clusters`, `pre_cve_cluster_members`, and `pre_cve_dispositions` relations. Cluster identity is `(vendor, product)` + a 7-day `first_seen_bucket` (generated column) so concurrent creation is idempotent under the unique constraint — no read-then-insert race.
- **`server/correlation/clusters.ts`** — `linkPreCveClusters()` runs **inside the ingest transaction** (`ingest.ts` was wired accordingly), so advisory + matches + cluster membership commit atomically; a crash can never orphan a cluster. `bindClusterToCve()` attaches the published CVE and propagates dispositions.
- **`src/types/index.ts` / `src/utils/intelligenceMatcher.ts`** — `IntelligenceArticle` now carries `clusterId`/`resolvedCveId`; `mergeArticles` preserves both across feed merges; a cluster-resolved article contributes to the canonical CVE match **even without keyword corroboration**, so the CVE inherits rather than re-alerts.

**Residual risk (accepted, documented).** Clustering on `(vendor, product)` is deliberately coarse: two *distinct* zero-days in the same product inside the 30-day window collapse into one cluster. This is the correct error direction — over-merging produces one review item, under-merging produces an alert storm. Phrase-level fingerprints (`textFingerprint`) are provided for operator adjudication, not automatic merge, because adversarial feeds can forge shared shingles.

#### 1.2 Heuristic Keyword False-Positive Avalanche — findings and fix

**Observed failure.** The n-gram alias lookup in `engine.ts` built **every 1–4-gram of the entire normalized article** and matched them against `vendor_product_aliases`. A sensationalized headline — "Critical flaw exposed in mainstream enterprise servers" — emits grams such as `flaw exposed in`, `mainstream enterprise servers`, `in mainstream`, each of which enters the 101-row alias budget. If the alias table contains broad seeds (`k8s`, `exchange server`, …), a single article can saturate the budget with junk candidates and push *real* aliases out (a first-row-wins starvation the `LIMIT 101` silently enforces). The `zeroDay` keyword list additionally counts `vulnerability` and `exploit`, which appear in *every* security article, inflating `securitySignal` and upgrading LOW matches to MEDIUM across unrelated inventory.

**Fix applied.** `engine.ts` now filters every gram through a curated stopword set (grammatical tokens **and** generic security vocabulary: `flaw`, `vulnerability`, `exploit`, `critical`, `servers`, `researchers`, …) and rejects single-character tokens. Generic phrasing can no longer become an alias candidate; only identity-plausible tokens (`fortios`, `pan-os`, `exchange server`) survive. This bounds the false-positive blast radius at the *candidate-generation* stage rather than downstream, where the 1000-match fanout cap would only convert the storm into a `MATCH_FANOUT_LIMIT` exception and a dead-lettered advisory (a data-loss window of its own).

#### 1.3 Cross-Source Indicator Fragmentation — findings and fix

**Observed failure.** A vendor advisory using an internal reference (`cisco-sa-…`) and a news outlet describing the same flaw with different phrasing produced **orphaned, unlinked records**: different `fingerprint`s, different `assetId` match rows in `correlation_matches`, and no join key. The pre-CVE cluster table now supplies that join key (§1.1). Additional fragmentation hazard fixed: the extraction band regex (`between X and Y`) previously produced ranges with an **empty `productPhrase`**, which `engine.ts` matched to nothing — silently discarded evidence. The band ranges now attach to the single unambiguous alias when `aliases.rows.length === 1`, consistent with the existing single-product inference rule.

---

### 2. General Matching Failures, False Positives & Range Logic Flaws

#### 2.1 Version evaluation gap (natural-language bounds) — findings and fix

**Observed failure.** `evaluateVersion()` accepted only the strict comparator grammar (`>=1.0 <2.0`). Real advisory prose — "patched before version 9.0.86", "vulnerable between 2.1.0 and 2.3.4" — fails the term regex and returns `REVIEW`. The engine then inserts a **LOW-confidence row into `low_confidence_review_buffer` for every asset of that vendor/product** (the no-range branch was *not* taken on REVIEW; `engine.ts` line 132 adds a LOW review match). At enterprise inventory scale this is a review-queue flood, and the `UNAFFECTED` path was unreachable for such prose — so patched estates were never *excluded*, only permanently reviewed.

**Fix applied.** `server/correlation/version.ts` adds `naturalLanguageRange()` translating five prose families before the comparator runs:

| Prose | Translated range |
|---|---|
| "patched/fixed in X", "before/prior to/below/earlier than X" | `<X` |
| "between/from X and/to/through Y" | `>=X <=Y` (semver-coerced, `null` on incoercible input) |
| "X and earlier / or older / or below" | `<=X` |
| "X and later / or newer / or above" | `>=X` |

Untranslatable prose still yields `REVIEW` — **never** a silent identity fallback. The extraction worker (`extraction.ts`) gained a second bounded pass capturing inclusive bands at ingest time (note: template literals are illegal inside the `String.raw` worker source, so the range string is built by concatenation — this was a real parse failure caught by the test run).

#### 2.2 Version format clipping (backport suffixes) — findings and fix

**Observed failure.** The prior code's *comment* promised "never discard distribution/backport suffixes" for the asset version, but the **range-bound** path used the same `portableVersion()` for bounds; worse, nothing distinguished `1.2.3-ubuntu1~20.04.1` (a distro rebuild that patches the CVE *without* changing the upstream base) from `2.4.41-2` (Debian revision). Both fell to `REVIEW`, which is safe — but the SQL mirror in `015_version_range_pushdown.sql` diverged: its `portable_version` regex `^-\d+$` rejection and 4-component `version_ordinal` disagree with the TypeScript semantics, and its `version_satisfies` **always returns `'REVIEW'`** (line 123), so any caller of the pushdown path silently converts every verdict into a review row. That is a false-positive generator wearing a performance optimization.

**Fix applied.** `distributionSuffix()` classifies Debian/RHEL (`1.2.3-ubuntu1~20.04.1`, `2.4.41-el8`) and Java-ordinal (`1.8.0_392`) forms explicitly and short-circuits to `REVIEW` **before** the comparator — with a carve-out for named upstream prereleases (`rc`, `beta`, …), which was the bug my first cut introduced and the regression test `version ranges preserve release candidates…` caught. The policy is recorded in `017_suffix_policy.sql`. The `015` SQL stub is now *known-broken-by-design* and documented as such: any production enablement of the pushdown must implement the TypeScript semantics in PL/pgSQL or gate behind the `semver` extension — shipping a comparator that always says REVIEW is worse than not shipping it.

#### 2.3 Thesaurus naming drift — findings and fix

**Observed failure.** Three compounding defects:

1. **Migration 016's `fuzzy_asset_lookup` used OR between vendor and product similarity.** An article mentioning "Microsoft" alone matched every Microsoft asset regardless of product — the textbook cross-product false-positive storm the audit prompt describes. `fuzzy_alias_lookup` accepted `similarity >= 0.6` with **no minimum length**, so a 4-char token (`java`) fuzz-matched `kafka`, `jboss`.
2. Both functions were **granted to PUBLIC**, putting a fuzzing oracle over the entire corpus within reach of any session — a data-exfiltration and match-poisoning surface.
3. `intelligenceMatcher.ts` `mentions()` performs whole-token containment (` ${document}.includes(' ${normalized} ')`), so a single over-general Thesaurus alias (e.g., mapping `teams` → `microsoft/teams`) fires on any article containing the pluralized/generic token, and since the matcher iterates **all active assets × all articles × all CVE references**, one bad alias rows multiplies across the entire inventory each run.

**Fix applied.** `server/migrations/019_fuzzy_alias_hardening.sql` replaces both functions: similarity threshold raised to **0.75**, conjunctive (AND) vendor+product matching with `LEAST()` ordering, minimum normalized lengths (6 for aliases, 4 for product identity), and the PUBLIC grants revoked. The exact-match engine path (`lower(alias)=ANY($1)`) is untouched — it remains the ingestion trust boundary; fuzzy lookup is now an operator utility only.

---

### Cross-cutting verification

- **Migrations 17–22** registered via the directory-driven runner; `REQUIRED_SCHEMA_VERSION = 22`; `tests/migrations.test.ts` now enforces unique, gap-free version numbers in addition to the marker and newest-version gates.
- **Regression coverage:** the version-comparator, extraction-worker, NDJSON, dead-letter, matcher and (now actually executed) PostgreSQL-backed correlation suites all pass, confirming the suffix carve-out and the worker-string fix did not regress the strict grammar path.
- **Deliberate non-changes:** the 1000-match fanout cap, worker-isolated regex budget, lease/`SKIP LOCKED` pending semantics, and transaction retry ladder were audited and found sound; they were not modified.

---

### 3. Deployment-Blocking Defects Found Only By Running Against A Real Database

Every defect below was **invisible to a source-only audit** and to a test run without `TEST_DATABASE_URL` (which silently skipped all 10 DB tests). They are listed separately because each one made the pipeline either non-functional or silently wrong.

#### 3.1 The correlation pipeline had never ingested successfully

`operational_events` was created in migration 002 with the pipeline-event shape (`category`, `code`, `message`, `run_id`, `context` — the latter three `NOT NULL`). The correlation telemetry writer inserts a *different*, per-worker shape (`sequence`, `event`, `tracking_id`, latency columns). On any fresh database:

```
error: column "sequence" of relation "operational_events" does not exist
```

This ran **inside** the advisory transaction, so *every* ingest rolled back and was dead-lettered. Because telemetry is persisted before commit by design (crash durability), a telemetry schema defect is a total pipeline outage — not a degraded log.

**Fix — `022_operational_events_telemetry.sql` + `telemetry.ts`:**
- Telemetry columns added additively; pipeline columns retained.
- Correlation severities mapped onto the stored vocabulary (`WARN` → `WARNING`, `CRITICAL` → `ERROR`). The 002 `CHECK` constraint rejects raw values, which caused a *second* failure on the retry path.
- The three `NOT NULL` pipeline columns are now populated for telemetry rows instead of omitted.
- **String-interpolated SQL replaced with bound parameters.** The old writer concatenated `VALUES` literals, so an apostrophe in an event name broke the insert, and an attacker able to influence a log event had SQL injection into the write-ahead log. Parameter offsets are position-checked — the first cut produced `could not determine data type of parameter $16`, caught by the same test.

#### 3.2 Duplicate migration versions silently dropped migrations

The runner hard-coded each filename. Two pairs shared a number:

| Version | Files | Applied |
|---|---|---|
| 014 | `014_concurrent_indexes.sql`, `014_shared_correlation_concurrency.sql` | second only |
| 015 | `015_version_range_pushdown.sql`, `015_correlation_lease_ownership.sql` | second only |

The consequence was not merely dead code: `015_version_range_pushdown.sql` created `portable_version`, `version_ordinal` and `version_satisfies`. My migration 020 tried to `REVOKE` them, so 020 aborted its transaction and took all 22 migrations with it.

**Fix:**
- Both shadowed files retired to `server/migrations/retired/` (outside the runner's pattern).
- **Hard-coded list replaced with a directory scan** (`migrationFiles()` in `db.ts`), sorted by numeric prefix, skipping applied versions. A new migration can no longer be forgotten — and one cannot be shadowed.
- Migration 020 is **self-contained**: it creates `portable_version` and `version_ordinal` itself rather than assuming 015 ran.
- `tests/migrations.test.ts` gained two guards: **version numbers unique and gap-free**, and every file matching the runner's pattern.

#### 3.3 `CREATE INDEX CONCURRENTLY` inside the migration transaction

Migrations 014 and 016 used `CONCURRENTLY`. PostgreSQL rejects it inside a transaction block, and `migrate()` wraps every file in one — both files aborted the entire migration history. 016 additionally assumed `pg_trgm` was installed and ran `UPDATE` against **generated** columns, which PostgreSQL rejects.

**Fix — `016_trigram_alias_lookup.sql` rewritten:**
- Plain `CREATE INDEX` (transactional; safe).
- `CREATE EXTENSION pg_trgm WITH SCHEMA <current_schema()>` in an exception handler. Installing into `public` from a schema-isolated tenant leaves `similarity()` and `gin_trgm_ops` unreachable — the first attempt failed exactly there, and a `pg_extension` probe then lied, so the guard now requires the extension to be installed **in a schema on this session's `search_path`**.
- Trigram indexes are conditional; the migration succeeds without `pg_trgm` (verified on a second database with the extension dropped).
- `UPDATE` on generated columns removed.

#### 3.4 `assets` is owner-managed — migration 016 violated the contract

`tests/correlation.test.ts` asserts the `assets` column list is unchanged after migration. Migration 016 added generated `normalized_vendor`/`normalized_product` columns and a `fuzzy_asset_lookup()` reading them. Only a real-DB run executes that assertion.

**Fix:** columns, indexes and `fuzzy_asset_lookup()` removed from 016 and 019. Nothing called the function, and the alias lookup on `vendor_product_aliases` (module-owned) is what the design needed. The §2.3 *conjunctive* semantics were right; their *location* was not.

#### 3.5 `HIGH` priority bypassed the global worker ceiling

`supervisor.acquire()` skipped **every** limit for `HIGH`, including the hard `concurrencyLimit`. A burst of CVE-bearing advisories — precisely what a zero-day disclosure produces — opened unbounded workers and exhausted the pool, starving the queue it was meant to prioritize. The concurrency test observed 8 concurrent workers against a ceiling of 2.

**Fix:** `HIGH` still bypasses *soft* backpressure (memory shedding, DB-severance recovery) but respects the global ceiling and its own pool limit. This is the backpressure analogue of the §1.2 false-positive avalanche: an unbounded fast path is an outage waiting for load.

#### 3.6 Least-privilege role could not write the new cluster tables

`grantRuntimePrivileges()` enumerates tables explicitly; the cluster tables were not listed, so every ingest and review decision failed `42501` under the restricted runtime role — the production posture. Added `SELECT/INSERT/UPDATE` on `pre_cve_clusters` and `pre_cve_dispositions`, `SELECT/INSERT` on `pre_cve_cluster_members`.

### 4. Authorization And Test-Isolation Defects (closing the last 3 failures)

The remaining failures were genuinely three different problems wearing the same symptom:

#### 4.1 `/api/correlation/simulate` was not actually read-only
It sat behind `requireRole('ADMIN')` **and** the global mutation quota, although it performs a pure in-memory match against already-loaded data and writes nothing. Consequences:
- A VIEWER — documented as read-only, not blind — could not use it at all.
- An OPERATOR exploring the matcher burned their write quota, so curiosity about matching cost them the ability to change configuration.

**Fix:** opened to `ADMIN`, `OPERATOR`, `VIEWER`, and removed from the mutation quota via an **exact-route, method-scoped allowlist**. Never a prefix, so a future mutating route cannot inherit the exemption by naming.

#### 4.2 The quota middleware silently exempted nothing
The first attempt matched `req.path` against `/api/correlation/simulate`. Inside `app.use('/api', …)`, `req.path` is the path *relative to the mount* (`/correlation/simulate`), so the check matched nothing and the exemption was inert. Caught because the test asserts the behaviour rather than the code shape. Now uses `req.baseUrl + req.path`.

#### 4.3 Two tests were asserting the wrong thing
- `mutation quota is shared across application replicas` called `/api/correlation/simulate` as its "mutation". Once the endpoint was correctly exempt, the test could never produce a 429. It now issues a **real OPERATOR-permitted mutation** (`asset.save`), resets its own quota bucket first (buckets persist across runs and replica pools), and **separately asserts** that a read-only simulation still works *after* the write quota is exhausted — pinning both behaviours instead of conflating them.
- `roles enforce write and administration boundaries` logged in a **VIEWER** and expected a write to succeed. A VIEWER has no mutating endpoint, so the test was really asserting the 403 path. The quota test now uses an OPERATOR, which is the role the scenario describes.

A test that fails on clean HEAD is not automatically a broken test — here one was a real product defect (4.1) hiding behind two stale expectations (4.3).

### Residual risks to schedule

1. **Cluster window is operator-tunable** (`correlation_policy.pre_cve_cluster_window_days`, CHECK-bounded 1–180, default 30). Two distinct zero-days in one product inside the window still merge — the safe direction (one review row instead of an alert storm), but an operator should know the trade-off.
2. **`bindClusterToCve` is wired but only covered at the repository level.** It runs in `pipeline.ts` for each newly published CVE, and suppressed findings persist as `FALSE_POSITIVE`/`NOT_APPLICABLE` so a later run cannot resurrect them. A full pipeline run exercising publication is not in the suite.
3. **`pre_cve_dispositions` is now written by `decideCorrelationReview`**, but there is no UI showing cluster lineage; operators see the ruling on the article they reviewed, not the cluster it belongs to.
4. **`version_satisfies()` is correct but uncalled.** Verified 7/7: `>=2.0.0 <3.0.0` splits correctly, while distro suffixes, prereleases, bare integers and single-bound ranges all return `REVIEW` (matching the TypeScript paths for the same inputs). The pushdown it was written for was never implemented; wiring it into `buildCandidatePairs()` needs a benchmark, not a hunch.
5. **`CREATE EXTENSION pg_trgm` needs superuser.** Without it the trigram index is skipped and the migration still succeeds — a deployment that expects the index must grant it deliberately.
6. **The read-only exemption is a hand-maintained allowlist.** Adding a second non-mutating POST requires remembering to list it; the failure mode is only a consumed quota token, not a security hole, but it is a maintenance obligation worth a code comment at the route (which is present).
