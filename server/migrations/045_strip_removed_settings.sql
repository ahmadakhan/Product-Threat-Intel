-- Strip settings keys the application no longer reads.
--
-- `autoDispatchEnabled` and `confirmedFindingThreshold` were removed when the
-- finding gate was removed: every finding is dispatched and the advisory states
-- its own limitation, so neither key changes behaviour. Leaving them in the
-- stored row is not harmless. Anything that builds effective settings as
-- `{ ...DEFAULT_SETTINGS, ...stored }` still merges them, so an operator's
-- long-deleted preference silently outranks the shipped default and the stored
-- configuration describes controls that no longer exist.
--
-- Migration 042 renamed the threshold key; this removes the pair outright. It is
-- deliberately its own migration: 042 has already run on existing installations,
-- so editing it would only affect fresh installs and leave upgraded ones dirty.
UPDATE records
   SET data = data - 'autoDispatchEnabled' - 'confirmedFindingThreshold'
 WHERE kind = 'settings'
   AND id = 'main'
   AND (data ? 'autoDispatchEnabled' OR data ? 'confirmedFindingThreshold');

INSERT INTO schema_migrations(version) VALUES(45) ON CONFLICT DO NOTHING;
