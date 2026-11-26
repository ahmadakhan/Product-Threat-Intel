-- JSONB expression indexes for the `records` EAV table.
--
-- Every collection query in `server/collections.ts` filters on `kind=$1`
-- before applying JSONB predicates. A composite index on
-- `(kind, <jsonb expression>)` lets PostgreSQL satisfy equality filters and
-- sort predicates with an index scan instead of a JSONB extraction per row.
--
-- These statements are applied through `applyIndexMigrations()` outside any
-- transaction, one statement at a time, with `CREATE INDEX CONCURRENTLY`.
-- Adding an index means adding it here, never to a NNN_*.sql migration file.
--
-- Match the exact expression form used by `recordConditions()` and
-- `orderClause()` in `server/collections.ts` so the planner can use the index.
-- Operators and casts must be identical: `data->>'status' = $1` uses a
-- text equality, so the indexed expression is `(data->>'status')`.

-- Findings: notificationStatus and status are the most selective filters.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_notification_status
  ON records(kind, (data->>'notificationStatus'))
  WHERE kind = 'findings';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_status
  ON records(kind, (data->>'status'))
  WHERE kind = 'findings';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_severity
  ON records(kind, (data->'cve'->'cvss'->>'severity'))
  WHERE kind = 'findings';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_execution_id
  ON records(kind, (data->>'executionId'))
  WHERE kind = 'findings';

-- Advisories: deliveryStatus filter.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_advisories_delivery_status
  ON records(kind, (data->>'deliveryStatus'))
  WHERE kind = 'advisories';

-- CVE data: cisaKev.isKev and modifiedDate are heavily filtered/sorted.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_cvedata_is_kev
  ON records(kind, (data->'cisaKev'->>'isKev'))
  WHERE kind = 'cveData';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_cvedata_modified_date
  ON records(kind, (data->>'modifiedDate'))
  WHERE kind = 'cveData';

-- Email logs / webhook logs: status, sentAt, advisoryId filters and sorts.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_email_logs_status
  ON records(kind, (data->>'status'))
  WHERE kind = 'emailLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_email_logs_sent_at
  ON records(kind, (data->>'sentAt'))
  WHERE kind = 'emailLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_email_logs_advisory_id
  ON records(kind, (data->>'advisoryId'))
  WHERE kind = 'emailLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_email_logs_provider
  ON records(kind, (data->>'provider'))
  WHERE kind = 'emailLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_email_logs_delivery_group
  ON records(kind, (data->>'deliveryGroup'))
  WHERE kind = 'emailLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_webhook_logs_status
  ON records(kind, (data->>'status'))
  WHERE kind = 'webhookLogs';
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_webhook_logs_sent_at
  ON records(kind, (data->>'sentAt'))
  WHERE kind = 'webhookLogs';

-- Executions: status filter and startTime sort.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_executions_status
  ON records(kind, (data->>'status'))
  WHERE kind = 'executions';

-- Alerted CVEs: status filter.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_alerted_cves_status
  ON records(kind, (data->>'status'))
  WHERE kind = 'alertedCves';
