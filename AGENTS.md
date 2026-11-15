# AGENTS.md

## Lint and Typecheck

```bash
npm run lint           # tsc --noEmit — run before every commit
```

Tests:

```bash
npm test                # node --import tsx --test (all tests)
npm run test:unit       # supported node:test suite (alias of npm test)
npm run test:ci         # requires TEST_DATABASE_URL; use a disposable database
```

ML subsystem only:

```bash
node --import tsx --test --test-concurrency=1 tests/ml-*.test.ts
```

ML training cron (standalone):

```bash
node --import tsx server/ml/train/cron.ts
```


## Running the Test Suite

The suite has two tiers. Unit files run with no infrastructure; database-backed
files read `TEST_DATABASE_URL` from the environment at module load and register
themselves as skipped (`{ skip: !database }`) when it is absent. 34 of the 109
`tests/*.test.ts` files take the second tier, so a `npm test` without a
database passes, but it proves only the unit tier: 88 tests are reported as `# SKIP`
and are silently unverified.

Point the run at a disposable database that contains neither real data nor your
development database:

```bash
# local PostgreSQL 16 (this repo's compose.yaml serves it on 127.0.0.1:5433)
createdb -h 127.0.0.1 -p 5433 -U postgres vulnstream_test_scratch
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/vulnstream_test_scratch' npm test
dropdb -h 127.0.0.1 -p 5433 -U postgres vulnstream_test_scratch
```

What a full run looks like with a database:

| Run | Result |
| --- | --- |
| `npm run lint` | exit 0 |
| `npm test` (no database) | 1070 passing, 0 failing, 88 skipped |
| `npm test` (with `TEST_DATABASE_URL`) | 1324 passing, 0 failing, 0 skipped |
| `npm run test:ci` (with `TEST_DATABASE_URL`) | exit 0 |

`test:ci` requires `TEST_DATABASE_URL` and fails fast without it; it does *not*
fall back to `localhost:5433`. `tests/global-setup.ts` does probe
`localhost:5433`/`127.0.0.1:5433` for the Vitest runner, but its permission to
run is governed by the same opt-in rule. If no database is reachable the two
fallbacks are skipped, so database suites are skipped too (do not treat this
as a failing suite on a machine without PostgreSQL — that is by design). If you're
running in CI, however, set
`VULNSTREAM_REQUIRE_TEST_DB=true` so a missing database is a hard red build
instead of a green run with skips. `CI=true` is treated the same way.

### The Vitest/node:test shim gap

`npm test` runs under the Node test runner. Vitest is also runnable over the
same files (`node node_modules/vitest/vitest.mjs run`; the `.bin/vitest) symlink
is not executable in this checkout, so call it through `node`). Vitest has no
`node:test` implementation, so `vitest.config.ts` rewrites the `node:test`
import of every file to the shim in `tests/node-test-compat.ts`.

The shim currently implements only `test(name, fn)`, `test(name, options, fn)`,
the `.skip`/`.todo`/`.only` shorthands, nested `t.test()` and `t.diagnostic()`.
It does **not** implement `t.mock` (Node's `MockTracker`: `fn`, `method`,
`getter`, `setter`, `reset`, `restoreAll`), and `vitest.config.ts` does not load
it through `test.setupFiles`; the rewrite happens in a plugin instead. As a
result:

- tests that call `t.mock.method(...)` pass under `npm test` and fail under
  Vitest with `TypeError: Cannot read properties of undefined (reading
  'method')`;
- a green Vitest run is not yet equivalent to a green `npm test` run.

**Use `npm test` (with `TEST_DATABASE_URL` set) as the authoritative gate.**
Do not port suites full of `t.mock.*` calls to Vitest until the shim supports
the tracker; if a Vitest run is needed meanwhile, run only suites that don't use
`t.mock`, or record their known divergence against the Node run.


## New Agent: Email Delivery Action Center

**File:** `src/components/ActionCenter.tsx`

The Action Center provides comprehensive email delivery monitoring and management:

**Key Features:**

- Real-time SLA monitoring with delivery rate, average delivery times, and compliance tracking
- Bulk operations (retry, cancel, send now) for multiple email logs
- Advanced filtering by status, provider, date range, and recipient type
- Interactive table with status badges, SLA indicators, and action buttons
- Auto-refresh every 30 seconds for live metrics
- Search functionality for finding specific deliveries by recipient, subject, or advisory

**Navigation:**

- Added to "Autonomous pipeline" section in sidebar
- Accessible via `/autonomous-pipeline/action-center`
- Also available as "Email delivery action center" in main navigation

**Permissions:** Requires ADMIN or OPERATOR role for management actions

**Components:**

- Email delivery SLA metrics dashboard
- Delivery status monitoring with real-time updates
- Bulk action toolbar for selected logs
- Advanced filtering and search interface
- Email queue management with retry capabilities
- Delivery timeline and history tracking
