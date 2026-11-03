# Audit working notes

## Baseline

- lint: PASS (tsc --noEmit, exit 0)
- tests: running in background

## Candidates

- main.ts: timers OK (unref present), shutdown present
- config.ts: strict zod schema, egress allowlist, OK
- retention.ts: auditLogs in TIMESTAMP_FIELDS, OK (42978ce fix present)
- pipeline.ts: enrichment pass (lines ~1390-1420) runs BEFORE runVulnerabilityPipeline (line 1553) — ordering correct
- Next: app.ts routes, db.ts pool config, rateLimit.ts, delivery.ts, network.ts
