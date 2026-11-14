-- Low-confidence correlation alerts are on by default.
--
-- This deployment is an autonomous, non-human-operated system: there is no one
-- watching a review queue, so evidence that a human should have reviewed must
-- still reach the security team. Withholding a MEDIUM/LOW vendor+product
-- correlation meant the advisory was ingested, correlated, and then silently
-- dropped — the only observer was an operator who did not exist.
--
-- Migration 043 introduced the switch with DEFAULT false to preserve the old
-- filtering. That preserved a failure mode rather than an intent: a fresh
-- installation delivered nothing until someone changed a setting. The switch is
-- kept as an opt-OUT for operators who deliberately want high-confidence-only
-- delivery.
ALTER TABLE correlation_policy
  ALTER COLUMN low_confidence_alerts_enabled SET DEFAULT true;

-- Existing installations that never made a choice flip to the new default. A
-- deliberate opt-out remains possible at any time, and afterwards this statement
-- no longer applies to it (the migration runs once).
UPDATE correlation_policy
   SET low_confidence_alerts_enabled = true,
       -- A backlog of historical matches must not arrive as one burst: enabling
       -- alerts starts the window from now, exactly as turning the switch on by
       -- hand does.
       notifications_since = CASE
         WHEN notifications_enabled THEN now()
         ELSE notifications_since
       END,
       updated_at = now()
 WHERE id = 1
   AND low_confidence_alerts_enabled = false;

INSERT INTO schema_migrations(version) VALUES(44) ON CONFLICT DO NOTHING;
