# Matching audit: vendor/product mapping, CPE alignment, wildcard matching, news extraction

Scope: the four automated correlation paths that decide which inventory item a
record is attached to. This is an evidence framework, not a summary of intent: it
states what must be measured, how each property is verified, what "zero duplicates
and perfect fidelity" means operationally, and which findings were fixed in code.

The four processes map to these modules:

| Process | Primary implementation |
| --- | --- |
| Vendor-to-product mapping | `src/utils/cpeMatcher.ts` alias thesaurus; `server/correlation/engine.ts` Tier 2; `src/utils/intelligenceMatcher.ts` variants |
| CPE alignment | `src/utils/cpeMatcher.ts` (`parseCPE23`, `matchCPE`, `matchesWatchlistItem`) |
| Wildcard pattern matching | `cpeMatcher.ts` (`globIntersects`, `resolveGenericCpeIdentity`); `server/correlation/version.ts` for ranges |
| News entity extraction | `src/utils/intelligenceMatcher.ts` (`matchIntelligence`, called from `server/pipeline.ts`); `server/correlation/extraction.ts` |

Every property below is either enforced by a committed test or measured by
`npm run matching:evaluate`. A property that is only described but neither
measured nor tested is called out as a residual risk.

---

## 0. Measurement baseline (applies to all four)

### Required evidence (baseline)

- A labelled corpus, `tests/fixtures/matching-corpus.ts`, where every case names
  the expected decision *and* the expected evidence class (`expected.methods`).
  A right answer for the wrong reason is a failure.
- Per class and pooled: precision, recall, **F1**, and the **95% Wilson lower
  bound** for precision and recall. The point estimate alone is not evidence on a
  small corpus: 15/15 positives gives 100% precision but a 95% lower bound of
  ~79.6%, which is what a reviewer should actually rely on.
- Confusion counts (TP/FP/FN/TN) and the list of false positives at or above the
  auto-dispatch threshold (90).

### Verification (baseline)

```bash
npm run matching:evaluate   # prints F1 and 95% lower bounds per class; exits non-zero on a gate breach
node --import tsx --test tests/matching-quality.test.ts
```

Gates (`MATCHING_QUALITY_GATES`): precision >= 0.95, recall >= 0.9,
high-confidence false positives = 0. `npm run matching:evaluate` exits non-zero on
a breach, so the gate can be wired into CI as-is.

### Integrity (baseline)

- Every corpus id is unique and every positive names a non-`NONE` method
  (enforced in `tests/matching-quality.test.ts`).
- Determinism is measured separately by `evaluateDeterminism`: three runs per case
  must yield the same decision tuple (`matched|method|confidence|packageVerdict`).

### Residual risk (baseline)

The corpus is curated, not sampled from a production feed, so its confidence
bounds describe the labelled set, not the customer corpus. To make a claim about
production precision, label a random sample of real findings (at least 300, per
evidence class) and run `evaluateMatchingCorpus` over it. Until that is done, the
fidelity claims below are "verified on the labelled corpus", which is the honest
scoping.

---

## 1. Vendor-to-product mapping

### Required evidence (1)

- For every (vendor, product) the matcher can propose, the alias group that
  justified it, and whether that group is built-in or operator-supplied.
- Precision/recall/F1 on the `alias` and `fallback` corpus buckets, plus a
  dedicated negative set: a vendor-only mention, a shared vendor with a different
  product, a product named only as a modifier, and a language named only as a
  vehicle.
- A count of expansions per identity. An identity that expands to dozens of
  spellings is an accident waiting to happen and should be inspectable.

### Verification method (1)

- Symmetry: `matchVendorWithAliases(a, b)` must equal `matchVendorWithAliases(b, a)`
  for the whole alias table; the built-in table is verified by the alias suite.
- Symmetry of custom aliases: `mergeAliasTables` is memoised by table identity and
  frozen, so one operator edit cannot leak into another run's match.
- Name-collision check: alias keys are normalised with `normalizeAliasToken`
  (punctuation-insensitive, `+`/`#` preserved), so `c++` cannot collapse to `c`.

### Integrity requirements (1)

- One decision per (vendor, product) pair per record. The pipeline's alias step
  returns on the first matching criterion and the caller takes the highest
  confidence; a second pass cannot add a second finding for the same asset.
- The vendor must be present in the text and not in an attributed role; the
  product must be the stated subject. This asymmetry is deliberate and documented
  at `proseAttributesExposure`.

### Findings and fixes (1)

- **F1 (fixed):** vendor/product attribution no longer uses an enumerated stop-list
  of platform, language and delivery words. That list is gone; a name it never
  contained (a newly shipped framework, a niche runtime) is handled by the same
  structural rule. The design, as implemented:
  1. **Product phrase, not product token.** The product must be stated as the
     affected subject in an exposure-stating clause. "Written in X", "an X plugin
     that allows", "X deployments" and negated sentences are refused.
  2. **Vendor in a distinct clause is enough.** The vendor only has to be named,
     because advisories routinely put the vendor in the headline and the product in
     the body ("Acme publishes a bulletin. A flaw in Widget allows ..."). It must be
     a different identity from the product, so a same-token name cannot satisfy
     both halves of the check.
  3. **Nested names are separated structurally.** A capitalised continuation
     followed by a head noun is another product's name ("the Acme PHP Builder
     plugin allows"); a capitalised continuation that runs into the predicate is the
     same subject with a longer name ("Acme Confluence Data Center is vulnerable").
     No product-name list is consulted.
  4. **Same-token identities** (`php`/`php`) are judged on the identity alone, and
     still refused when they are only an environment or a modifier.
  Pinned by `tests/prose-attribution.test.ts`, including the original reported
  failure (`php`/`php` vs the SourceCodester CVE) and the nested-name pair.
- **F2 (fixed):** the prose fallback evaluated the title and body as one string, so
  a headline could lend its identity to a body sentence that attributed it. It now
  evaluates per clause and per sentence with an explicit, bounded
  headline-continuation rule.

---

## 2. CPE alignment

### Required evidence (2)

- Round-trip integrity: for every CPE in the corpus, `parseCPE23` yields 11
  components and `raw` reproduces the input.
- Component-level accuracy against NVD's dictionary: the escaped and unescaped
  forms of the same CPE must compare equal
  (`normalizeCpeForComparison`), and `_`/`-`/`.` are formatting, not identity.
- Exact-token matches must dominate: the strict tier must be the method reported
  whenever identical vendor/product/version tokens agree.

### Verification method (2)

- Differential check against the NVD CPE dictionary for a sample of 1000 products:
  every advisory CPE whose vendor/product matches an inventory CPE must match at
  `STRICT_CPE`, and every non-matching pair must report a component mismatch
  reason (never "no correlation").
- Malformed-input stress: `parseCPE23` is fuzzed with truncated, over-escaped and
  over-component input; the parser must return `isValid: false` and never throw
  (covered by the parser suite).

### Integrity requirements (2)

- A CPE identity is exactly one vendor/product. A **structural glob** in the
  vendor or product field is not an identity assertion and is refused.

### Findings and fixes (2)

- **F3 (fixed):** `matchCPE` accepted a partial glob (`acme.*`, `wid?et`) in the
  vendor/product field. Combined with a candidate-set iteration that retains the
  first/highest-confidence intersection, that let a glob intersect an advisory for
  a *different* product and report a strict match. Two changes:
  1. `matchCPE` now returns `matched: false` with an explicit reason when either
     side's vendor or product is a structural wildcard.
  2. `resolveGenericCpeIdentity` reports `structuralWildcard` for a partial glob
     and no longer folds it into the inventory's declared name; the strict loop
     skips those entries. The engine's candidate prefilter already classifies the
     same CPEs as broad, so this makes the two paths agree.
  3. A substitution that sanitises to nothing, `-` (CPE "not applicable") or `*`
     is refused rather than producing an identity that names no product.
- **F3b (verified, no change):** an unasserted inventory version combined with a
  partial advisory wildcard stays review-gated; `confidenceIsLimited` requires
  both the scope flag and confidence >= 90, so a `1.*` family match cannot render
  as a full-confidence finding.

---

## 3. Wildcard pattern matching

### Required evidence (3)

- Non-emptiness of glob intersection: `2.*` vs `1.*` must be disjoint, `1.*` vs
  `1.2*` must overlap, `1.?` vs `1.2` must match.
- Pathological-input behaviour: 64-star patterns must terminate within the test
  budget and without throwing.
- Version-range verdicts must be tri-state (`IN_RANGE` / `OUT_OF_RANGE` /
  `INCONCLUSIVE`); an incomparable version must never be reported as affected.

### Verification method (3)

- Property-based check: for a generated set of (pattern, concrete version) pairs,
  `globIntersects(pattern, version)` must agree with a reference
  `RegExp`-based matcher. This is the standard way to catch a memoisation bug in
  the intersection algorithm.
- Regression gate: `tests/audit.test.ts`, `tests/cpe-auto-alias.test.ts` and the
  `wildcard`/`version` corpus buckets.

### Integrity requirements (3)

- A wildcard scope is a declared monitoring scope, not broadened evidence. It may
  raise the match to a normal 90% finding, but a *partial* version family must
  stay distinguishable from the all-versions scope (`wildcardScopeMatch` is
  false for `1.*`).
- Wildcards never cross a product boundary: `resolveGenericCpeIdentity` only
  resolves a complete `*`/`*` scope from the inventory's own declared names.

### Findings and fixes (3)

- **F3 (shared fix):** see above; the structural-glob refusal is the wildcard
  integrity fix.
- **Verified:** `matchComponent` treats `-` (not applicable) as a hard mismatch
  against any concrete value, and `*` as a match only at the top level
  (`hasUnescapedCpeWildcard` returns false for a lone `*`), which is what keeps
  `negative-wildcard-version-intersection` green.

---

## 4. News-based entity extraction

### Required evidence (4)

- Per article: the vendor variant and product variant that matched, and the
  normalised document the match ran against.
- Precision/recall on a labelled news set, plus two dedicated negatives: vendor
  mentioned alone, and product mentioned alone.
- Deduplication evidence: repeated article ids must collapse to one match with
  the union of article ids.

### Verification method (4)

- Vendor/product separation invariant: an article that names the vendor and a
  different product of that vendor must not corroborate the inventory item
  (`tests/matching-integrity.test.ts`, `tests/vendor-product-news-regressions.test.ts`).
- Extraction sandbox: `server/correlation/extraction.ts` runs its regexes in a
  disposable worker with a 200 ms budget and hard caps (100 CVEs, 100 ranges);
  catastrophic backtracking is a CPU-exhaustion vector and must be contained.
- Symbols: `visual_c++`, `visual_c#` and `visual_c` must stay three products
  through every normaliser used on the news path.

### Integrity requirements (4)

- **Both** vendor and product must be named; the only exception is a cluster that
  was explicitly resolved to a CVE (`clusterResolved`), which is a linked incident,
  not loose phrasing.
- News evidence may never override a structured exclusion. `authoritative` CVEs
  with no existing finding are skipped, and `NOT_APPLICABLE` /
  `SUPPRESSED_VEX_NOT_AFFECTED` findings are never re-confirmed by press coverage.
- Deterministic output: `mergeArticles` picks a winner by `modifiedDate` then by a
  total JSON ordering, so two runs over the same feed produce the same article set.

### Findings and fixes (4)

- **Verified:** the vendor-and-product requirement, the cluster exception, the
  structured-exclusion guard, and the dedupe-by-id behaviour are pinned by
  `tests/matching-audit.test.ts`.

---

## 5. Zero-duplicate output (cross-cutting)

The persisted finding store is keyed by a generated id, not by (CVE, asset), so it
cannot itself detect a duplicate. Duplicate integrity is therefore enforced at the
two places where a duplicate could be born:

1. **Within a run.** The pipeline holds a `known` set keyed `${cveId}:${assetId}`
   and skips a pair it has already emitted.
2. **Across a run.** New detections are gated on the publication event, and
   `includeExistingCandidates` controls whether known pairs are re-emitted.

### Finding and fix (F4)

Neither dedupe layer was independently observable, so a future regression in the
candidate loop would have silently produced duplicate findings. The run now
records every emitted `(CVE, asset)` key and, if the same pair is emitted twice,
writes a `MATCH_INTEGRITY_DUPLICATE_PAIRS` audit event and names the count in the
execution's matching phase. A clean run records nothing. This is a monitor, not a
substitute for the dedupe: it exists so the invariant is measured on every run
instead of assumed.

```bash
node --import tsx --test --test-name-pattern="exactly one finding" tests/matching-audit.test.ts
```

---

## 6. Residual risks (accepted, with the reason)

- **Curated corpus.** The precision/recall figures describe the labelled set. A
  production claim needs a labelled random sample; the tooling
  (`evaluateMatchingCorpus`) already accepts one.
- **Case-sensitive nested names (resolved, retained as a note).** A bare name that
  only begins another product's name was previously an accepted limitation. The
  structural rule now separates the two shapes by whether the capitalised
  continuation is followed by a head noun, so `Ferrum` in "Ferrum Builder plugin"
  no longer matches while `Confluence` in "Confluence Data Center is vulnerable"
  does. The remaining edge is a lower-case product name ("ferrum builder"), which
  has no case signal; such a mention falls back to the clause-role rule and, if
  ambiguous, stays at 70% review confidence.
- **Title-only advisories.** A title that is only `X security advisory` is accepted
  as a product registration when the document contains no other claim; a title that
  names an exposure (`X vulnerability`) is accepted as a claim. Both are
  review-visible at 70% confidence.
- **Extraction budget.** The correlation extractor refuses input whose regex
  evaluation exceeds 200 ms; that is a deliberate trade of some recall for
  bounded CPU, and the refusal is recorded as a dead letter rather than dropped.
