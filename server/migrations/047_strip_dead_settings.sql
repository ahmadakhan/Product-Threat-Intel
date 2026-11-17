-- Strip settings keys the application never reads.
--
-- None of these keys changed behaviour: no server or client module consulted
-- them, so an operator tuning them saw no effect. They were worse than inert.
--
--   * `ntpConfig` advertised an enabled/server/drift-tolerance control, but the
--     schema only ever accepted `enabled: false` with an empty server, so the
--     setting could not be switched on at all.
--   * `authorityPrecedence` described a source-precedence policy that matching
--     never applied; precedence is fixed in the correlation engine.
--   * `enrichmentMessageTemplate` was accepted by validation and never rendered;
--     the built-in evidence message is the only one produced.
--   * `ssrfProtection.allowRedirects` was accepted and ignored: feed fetches call
--     the redirect-aware client without consulting it. Egress policy is enforced
--     by EGRESS_ALLOWED_HOSTS and the per-request SSRF validation instead.
--   * `securityPolicy.csrfProtection` could only ever be `true`; CSRF checks are
--     unconditional.
--   * `webhookSigningSecret` was forced to the empty string by validation.
--
-- `ssrfProtection` goes entirely: both of its fields were fixed `true` in the
-- schema, so the object could never express anything but the enforced default.
-- A stored `{ ...DEFAULT_SETTINGS, ...stored }` merge would otherwise keep
-- describing controls that do not exist. Same reasoning as migration 045.
UPDATE records
   SET data = data - 'ntpConfig' - 'authorityPrecedence' - 'enrichmentMessageTemplate'
                    - 'ssrfProtection' - 'webhookSigningSecret'
 WHERE kind = 'settings'
   AND id = 'main';

-- Rebuild `securityPolicy` explicitly so the removed `csrfProtection` key cannot
-- survive, while every value the operator can still tune is preserved, and give a
-- row that predates the object entirely (older installs store no securityPolicy
-- at all) the shipped defaults. Leaving it undefined made the first login read
-- `settings.securityPolicy.maxLoginAttempts` and throw a TypeError.
UPDATE records
   SET data = jsonb_set(data, '{securityPolicy}', jsonb_build_object(
         'sessionTimeoutMins', COALESCE((data->'securityPolicy'->>'sessionTimeoutMins')::int, 30),
         'minPasswordLen', COALESCE((data->'securityPolicy'->>'minPasswordLen')::int, 14),
         'maxLoginAttempts', COALESCE((data->'securityPolicy'->>'maxLoginAttempts')::int, 5),
         'lockoutMins', COALESCE((data->'securityPolicy'->>'lockoutMins')::int, 15),
         'autoAliasTtlDays', COALESCE((data->'securityPolicy'->>'autoAliasTtlDays')::int, 30)))
 WHERE kind = 'settings'
   AND id = 'main'
   AND data <> '{}'::jsonb;

INSERT INTO schema_migrations(version) VALUES(47) ON CONFLICT DO NOTHING;
