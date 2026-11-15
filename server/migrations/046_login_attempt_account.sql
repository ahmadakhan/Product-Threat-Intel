--
-- 046 - Record which account each login-attempt bucket belongs to.
--
-- login_attempts counted failures per source key (`ip:<sha256(ip)>`) and per
-- account key (`user:<sha256(username)>`), but a source row carried no
-- reference to the account it was a failure for. The login throttle could
-- therefore only cap each key independently:
--
--   * the ip: bucket was capped at 5x the limit, so one shared NAT exhausted
--     it for every operator behind it on a single round of typos, and
--   * an attacker rotating source addresses never incremented any single
--     ip: bucket past the cap, while the user: bucket only ever saw the
--     final address, so there was no effective per-account cap.
--
-- `attempt_scope` stores sha256(username) -- the same non-reversible form the
-- `user:` key already uses, never the plaintext -- on the source row of every
-- failed attempt. That lets the login throttle count DISTINCT sources that
-- have failed against one account within the window and compare the count
-- against the account cap, so distributing guesses over many addresses does
-- not buy unlimited attempts. A single source that keeps failing is still
-- capped by its own ip: bucket (and stops appearing here once it is denied).
--
-- Pre-existing rows stay NULL: nothing recorded which account they were for.
-- Most rows in the table are per-source rows with a stable address, and the
-- throttle charges them against their own source bucket only; the roll-out
-- therefore does not lock out existing operators retroactively. Stale rows
-- are dropped by the retention sweep in server/main.ts.
ALTER TABLE login_attempts ADD COLUMN IF NOT EXISTS attempt_scope text;

INSERT INTO schema_migrations(version) VALUES(46) ON CONFLICT DO NOTHING;
