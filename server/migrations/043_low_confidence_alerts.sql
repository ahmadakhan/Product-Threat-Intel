-- Low-confidence correlation alerts.
--
-- A vendor+product correlation that is only MEDIUM (canonical entity, version
-- range unspecified or unverifiable) was previously withheld from everyone: the
-- notification query refused any advisory carrying a non-HIGH match. That hid a
-- real applicability signal from the security team, which is the opposite of what
-- the delivery layer documents ("native evidence is delivered regardless of
-- confidence").
--
-- The switch below makes that behaviour explicit and operator-controlled. It is
-- off by default, so an existing installation keeps its current filtering until
-- someone deliberately opts in; turning it on delivers those signals with a
-- prominent low-confidence notice naming every unconfirmed match.
ALTER TABLE correlation_policy
  ADD COLUMN IF NOT EXISTS low_confidence_alerts_enabled boolean NOT NULL DEFAULT false;

INSERT INTO schema_migrations(version) VALUES(43) ON CONFLICT DO NOTHING;
