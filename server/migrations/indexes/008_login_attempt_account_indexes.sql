--
-- 008 - Index supporting the per-account login lockout (migration 046).
--
-- CONCURRENTLY: every failed login inserts or updates login_attempts on an
-- unauthenticated path, so a SHARE-locked build would stall logins for the
-- whole installation while it ran. The builder refuses CONCURRENTLY inside
-- the schema transaction, which is why this lives here and not in 046.

-- The throttle counts DISTINCT attempt_scope values that have failed against
-- one account. Partial on NOT NULL because pre-046 rows carry none.
CREATE INDEX CONCURRENTLY IF NOT EXISTS login_attempts_scope
  ON login_attempts(attempt_scope) WHERE attempt_scope IS NOT NULL;
