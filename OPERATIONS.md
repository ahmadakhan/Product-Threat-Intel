# Operations

## Configuration and release

Keep `.env.production` out of source control and restrict host access. Protect database backups and the encryption key separately. Use a firewall to expose only 80/443 and your administrative access. Keep Docker, PostgreSQL, Caddy and Node base images patched; rebuild and test releases before rollout. The supplied image runs as a non-root user, with a read-only application filesystem, dropped capabilities and no privilege escalation. Set resource limits and monitoring to match your host and workload.

Release with `docker compose --env-file .env.production up -d --build`. Confirm the migration job exits successfully, `docker compose --env-file .env.production ps` reports healthy services, and sign-in, a pipeline and a test delivery work. Before upgrading, take a backup and test restoration. Do not run older code against a newer schema unless compatibility has been verified. Stop application traffic before a rollback requiring database restoration.

The runtime's `/live` endpoint reports process availability and `/ready` checks PostgreSQL. Neither certifies feed freshness or successful delivery. Monitor authenticated System Health, feed errors, execution failures, queue depth, failed deliveries, database size and worker heartbeat (normally updated every five seconds outside an active run). Alert on heartbeat staleness relative to your maximum ingestion time. Logs are JSON on standard output; retain and restrict access through your platform. Feed/provider error details may contain operational information.

## Back up

Run from the repository directory on the Docker host. Backups are consistent PostgreSQL custom-format dumps. Restrict destination permissions and encrypt off-host copies.

```sh
umask 077
mkdir -p backups
docker compose --env-file .env.production exec -T db pg_dump -U vulnstream_migrator -d vulnstream -Fc > "backups/vulnstream-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Check the command exit status and verify archive contents with `pg_restore --list`. Back up the protected deployment configuration and `ENCRYPTION_KEY` separately. Regularly restore to an isolated environment and verify accounts, inventory, audit history and decryption. A database dump alone cannot recover encrypted secrets without the matching key. Define backup frequency and retention from your recovery objectives.

## Restore

Restore into a fresh, isolated Compose project first. Initialize its database with the same database/role names and new protected database passwords. Keep `app` and `proxy` stopped. For example, with the intended project's environment and dump paths:

```sh
docker compose --env-file .env.production stop app proxy
docker compose --env-file .env.production up -d db
# This replaces data in the selected database. Confirm the target before running.
docker compose --env-file .env.production exec -T db pg_restore -U vulnstream_migrator -d vulnstream --clean --if-exists --exit-on-error < backups/SELECTED.dump
docker compose --env-file .env.production run --rm migrate
docker compose --env-file .env.production up -d app proxy
```

Use the encryption key corresponding to the backup. Restore tests must have external SMTP/webhook/feed egress blocked: restored pending jobs can resume. In a real recovery, reconcile provider receipts before restarting delivery to avoid duplicate messages. Sessions in the backup can be invalidated by an administrator running `DELETE FROM sessions` using the database owner role.

## Credentials and delivery

Rotate database passwords using PostgreSQL role administration and update the protected environment together. Re-enter feed/webhook credentials to rotate them. Changing `ENCRYPTION_KEY` does not automatically re-encrypt existing values: retain the original key, disable scheduling/delivery, and plan a controlled re-encryption migration before rotation. Never discard the old key until backups no longer require it.

SMTP uses TLS (implicit on 465, required STARTTLS otherwise), certificate validation and bounded timeouts. Generic webhooks carry `X-BA-Threat-Intel-Signature`, `X-BA-Threat-Intel-Timestamp` and `Idempotency-Key`; verify the HMAC over `timestamp + '.' + exact body` and reject stale timestamps at the receiver. Check the source for exact header casing (HTTP headers are case-insensitive). Slack/Teams payloads use their supported text format.

Jobs retry transient failures up to six attempts with backoff; permanent 4xx responses except 408/429 fail immediately. Failed jobs can be explicitly retried. A crash after remote acceptance and before local commit can duplicate a delivery, even with durable storage. Do not describe `ACCEPTED` as delivered/read. Use provider telemetry for those claims.

## Capacity and audit boundaries

This release uses a complete inventory/CVE snapshot for correlation and the UI, and serializes state-changing transactions. It is intended for a bounded organizational inventory; it has not been load-tested for a full historical NVD mirror or high concurrent operator counts. Measure representative ingestion, memory, response size and transaction latency before setting deployment capacity. NVD uses bounded daily incremental windows with a 50,000-result cap, EPSS queries only inventory-related CVEs, and response limits vary by adapter (8 MiB by default). Oversized feeds fail explicitly. Choose an appropriate ingestion window; do not silently assume a partial scan is complete.

The UI retains the latest 500 audit entries while the database retains the full chain. Application-role audit writes are append-only; a database owner can still alter schema/data or truncate history. Export audit records to independently controlled immutable storage if tamper evidence against administrators is required. No automated business-record retention/deletion policy is enabled; monitor storage and define an approved archival policy.

Matching does not implement every vendor version convention or full NIST applicability logic. Review flagged matches and vendor advisories. Live provider compatibility, public TLS issuance, restore objectives, accessibility and deployment load require acceptance testing in the target environment.

## Matching quality and alias governance

Run `npm run matching:evaluate` (also enforced in CI) to measure precision and recall on the labelled corpus in `tests/fixtures/matching-corpus.ts`. The report is broken down by evidence class and flags any expected-negative case that reaches the 90% auto-dispatch threshold. Adding a production mismatch to that corpus is the required regression step; the corpus currently covers 29 labelled cases and is a curated gate, not a statistical estimate over a full historical CVE mirror.

Alias behavior is deliberately conservative:

- Inventory aliases are derived from active assets and their own CPE identities, so they reconcile when the asset is renamed or removed.
- Correlation aliases are learned only from confirmed findings. Review-only fallback matches are not evidence.
- Automatic rows expire after 30 days without fresh support, then are deleted. Promote a row to make it a permanent operator alias; the automatic lifecycle will not modify or expire it.
- Revoke a row to create a tombstone. Revoked relations are not used for matching and are not re-learned; delete the tombstone to allow learning again.
- Text fallback requires whole identity words and ignores identities made only of words shorter than three characters (`os`, `ai`, `go`). Those products need CPE, PURL or explicit alias evidence.

### Feed timeout recovery

Threat Sources supports a request timeout (5–120 seconds) and recovery delay (1–60 minutes) per source. Existing sources retain adapter timeout defaults until configured. Failed ingestion schedules recovery after five minutes by default, doubling after repeated failures up to one hour. Automatic scheduled, catch-up, and recovery runs are opt-in through **Enable server scheduler**, which defaults off so starting the stack does not launch ingestion. Manual pipeline runs remain available. Successful ingestion clears the failure counter and retry deadline; disabling a source prevents automatic recovery. Retry deadlines appear beside failed sources and persist across server restarts. Automatic recovery requires both the scheduler and `WORKER_ENABLED=true` and can wait for an active pipeline to finish.

Feed ingestion has a total per-source budget controlled by `FEED_MAX_DURATION_SECONDS` (default 1800; range 1–7200). It includes pagination and retry waits; individual requests are capped to the remaining budget. A source exceeding this budget discards its incomplete response and enters automatic recovery. Empty EPSS scopes clear expired retry state without claiming verified connectivity. Loss of the worker lock connection prevents further source requests and commits. Ingestion phases report warnings when sources return partial parsing warnings.

### MITRE CVE source

The enabled `MITRE CVE — Official CVE List` source is added once on upgrade and on fresh deployments. It reads the official CVE Program repository at `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json`, then fetches CVE JSON 5 records by validated CVE ID. No API key is required. Add `raw.githubusercontent.com` to any custom `EGRESS_ALLOWED_HOSTS`; the bundled defaults already include it. Restart the server to run the source bootstrap. Operator changes and later deletions are preserved.

The adapter filters the rolling change log by its committed checkpoint, skips revisions already imported, and caps a run at 5,000 unique changed records. It uses the index ETag to avoid transferring an unchanged log. A changed log is still fetched as metadata because the provider does not expose an arbitrary since-checkpoint endpoint. Record requests run with at most three concurrent transfers, with all starts paced by the configured source rate. Checkpoints older than available delta history fail explicitly instead of silently skipping the missing period. Source request timeouts and the overall feed duration budget still apply. The log permits a 64 MiB response, and individual records permit 4 MiB.

Published records participate in the existing correlation engine; rejected records participate in withdrawal handling. CVE JSON version rules may contain exceptions or custom version schemes, so MITRE matches require applicability review and cannot initiate automatic dispatch on their own. CPEs, CNA product descriptions, CVSS metrics, CWE IDs and advisory references are retained. Canonical CVE-ID merging combines source attribution across MITRE, NVD and other feeds, while the existing CVE-and-asset finding identity prevents repeated findings across runs. Newer source revisions retain the existing revision-selection behavior.

### Incremental ingestion and caching

NVD, OpenCVE, MITRE and VulnCheck KEV maintain internal `feedCursors` records, bound to the source URL, adapter and credentials. Checkpoints, imported intelligence, findings and delivery jobs commit together. Failed, cancelled or obsolete-source runs do not advance a checkpoint. Credentials or endpoint changes invalidate the old checkpoint automatically. Existing installations bootstrap safely rather than trusting legacy `lastSync` timestamps as data-completeness checkpoints.

The initial sync fetches at most the selected lookback or 24 hours, whichever is smaller. Subsequent syncs resume from the committed watermark with a 10-minute overlap for delayed updates; they do not re-fetch the full selected lookback. A long outage is caught up in daily slices when the scheduler is enabled. Circuit cooldowns still apply. Broad scope selection does not request a full historical reimport; historical coverage requires a separate historical source/import. Correlation still evaluates all cached CVEs against current inventory on every run.

OpenCVE and MITRE retain recent per-CVE revision timestamps to avoid fetching unchanged detail documents in the overlap. MITRE advances only through the published log watermark and installs its ETag only after consuming that index completely. EPSS scores are cached for one hour per source and queried CVE set; newly matching CVEs are fetched immediately, and an expired cache refreshes all current candidates without extending old scores indefinitely. CISA KEV and RSS/JSON sources continue to use conditional requests where the provider supplies an ETag. VulnCheck KEV uses the documented last-modified date filters with 100-record pages and durable checkpoints. Catalog-only providers still require complete authoritative snapshots when changed; skipping portions could miss withdrawals or removals. Provider rate limits and initial-sync costs still apply.

RSS/Atom downloads and parsing share an 8 MiB limit and a 10,000-entry ceiling so large vendor archives (including MSRC) can be filtered to the selected time scope. XML entity/declaration restrictions remain enforced. Interrupted HTTP responses (including connection resets and aborted transfers) receive bounded retries in the provider adapters. A provider HTTP 401 requires checking its token and access; an undecryptable stored secret requires re-entry or restoration of the original encryption key.
