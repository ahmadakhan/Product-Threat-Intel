-- SUPERSEDED: a queued outbox row replaced by a newer revision of the same
-- document before it was ever sent.
--
-- A consolidated finding batch carries a content revision derived from the
-- findings it contains. When the batch is rebuilt at delivery time (a finding
-- went stale, or the matching policy now holds one), the rebuilt payload has a
-- NEW revision and therefore a NEW dedupe key. Any older job for the same
-- target still sitting QUEUED is that batch's earlier body: sending it delivers
-- a stale document, and for a webhook — which has no mailbox, so no delivery
-- claim deduplicates it — a second POST covering the same findings.
--
-- This is not 'REJECTED' (the transport refused the message) and not 'FAILED'
-- (the attempt did not succeed). Both would be counted against delivery health
-- in /api/state and kept for the full failure retention window, when the row
-- represents neither a failure nor something the operator must action. It also
-- must not stay 'QUEUED', or the worker would claim and send it.
--
-- Enforce the expanded constraint for new writes without scanning retained
-- outbox history under an exclusive table lock during deployment.
ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_status_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_status_check
  CHECK(status IN ('REVIEW','QUEUED','SENDING','ACCEPTED','FAILED','REJECTED','SUPERSEDED')) NOT VALID;

INSERT INTO schema_migrations(version) VALUES(41) ON CONFLICT DO NOTHING;
