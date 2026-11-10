-- Rename autoDispatchConfidenceThreshold -> confirmedFindingThreshold.
--
-- The threshold never withheld delivery: every finding is dispatched, and the
-- advisory states the limitation on the finding itself (there is no review
-- queue). The old name implied a gate, so operators configuring it expected
-- below-threshold findings to stop. The rename states what the value actually
-- chooses: how the finding is labelled (confirmed vs review-required).
--
-- Settings live in the `records` JSONB column, so this migrates the data in
-- place rather than altering a column. Idempotent: rows already migrated (or
-- rows that never had the old key) are untouched.
UPDATE records
   SET data = jsonb_set(
                data - 'autoDispatchConfidenceThreshold',
                '{confirmedFindingThreshold}',
                data->'autoDispatchConfidenceThreshold'
              )
 WHERE kind = 'settings'
   AND id = 'main'
   AND data ? 'autoDispatchConfidenceThreshold'
   AND NOT (data ? 'confirmedFindingThreshold');

INSERT INTO schema_migrations(version) VALUES(42) ON CONFLICT DO NOTHING;
