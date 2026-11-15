# AGENTS.md

## Project Context & AI Agent Guidelines

### 1. Strict Language Constraint

- You MUST think, reason, and respond EXCLUSIVELY in English.
- NEVER output Chinese characters (Hanzi) or full-width punctuation in your
  explanations, code comments, commit messages, or variable names.
- Use standard ASCII English characters only.

### 2. Tech Stack & Architecture

- **Stack:** TypeScript 5 (strict, ESM, `.ts` import specifiers), Node.js 26+,
  React 19 + Vite 8, Tailwind CSS 4, Express 4, PostgreSQL via `pg` with raw SQL
  (no ORM), Zod 4 validation, `node:test` runner.
- **Architecture:** the project is a single-component monolith serving the SPA
  and the API from one process. Keep it that way; do not split packages without a
  strong technical reason.
  - `src/components/` - React views, one file per page/tab.
  - `src/context/AppContext.tsx` - client state and all API calls.
  - `src/design/pages.ts` - page identity, titles, and sidebar sections.
  - `src/engine/` - pipeline, classification, matching, reconciliation.
  - `src/utils/` - pure, testable helpers.
  - `src/types/index.ts` - shared client/server domain types.
  - `shared/` - contracts imported by both sides (`state.ts`, `correlation.ts`).
  - `server/` - Express modules; routes are registered in `server/app.ts` under `/api/`.
    Entry point `server/main.ts`; migration runner `server/migrate.ts`.
  - `server/correlation/`, `server/ml/` - larger subsystems, own modules.
  - `tests/` - `node:test` suites plus fixtures and shared setup.
- **Migrations:** Schema and data changes go in `server/migrations/NNN_name.sql`
  (transactional). Never build an index inline on a populated relation in these
  files; index DDL lives in `server/migrations/indexes/NNN_name.sql` and runs as
  `CREATE INDEX CONCURRENTLY` outside a transaction. The numeric prefix is the
  ordering key, so it must be unique and gap-free. Each migration must record
  itself with
  `INSERT INTO schema_migrations (version) VALUES (NNN);`. `server/migrations/retired/`
  holds superseded, already-applied files; do not edit them.
- **Schema gate:** bump `REQUIRED_SCHEMA_VERSION` in `server/db.ts` with every new
  migration. `tests/migrations.test.ts` fails if it lags the newest file.
- **Routing:** the UI has no URL router. Pages are tabs in
  `src/context/AppContext.tsx` (`activeTab`), rendered by `src/App.tsx`, labelled
  and grouped by `src/design/pages.ts` and `src/components/Sidebar.tsx`. There are
  no `/autonomous-pipeline/...` or `/settings/...` URL paths. To add a page, add an
  entry to `pages`, a branch in `App.tsx`, and a Sidebar item.

### 3. Essential Commands

- **Install dependencies:** `npm install`
- **Run dev server (client + API):** `npm run dev:all`
  - Client only: `npm run dev` (Vite on http://127.0.0.1:3000, proxies `/api`)
  - API only: `npm run dev:server` (Express on http://127.0.0.1:8080, hot-reloaded)
- **Run linter & typecheck:** `npm run lint` (this is `tsc --noEmit`; there is no ESLint step)
- **Format:** `npx prettier --write <files>` (`singleQuote`, `trailingComma: all`, `printWidth: 110`)
- **Run tests:** `npm test` (`node --import tsx --test --test-concurrency=1 tests/*.test.ts`)
- **Run tests (CI parity):** `TEST_DATABASE_URL='...' npm run test:ci` fails fast without a database
- **Build:** `npm run build` (client bundle plus esbuild server bundle in `server-dist/`)
- **Run migrations:** `npm run db:migrate`
- **Seed dev data:** `npm run seed` (manual only; never run against production)

### 4. Coding Standards

- Prefer small, single-responsibility functions and strict typing. Do not add new
  `any`. The codebase still has legacy `any` (mostly in NVD/feed JSON parsing); do
  not spread it into new code.
- Parse external input at the boundary: Zod schemas in `server/config.ts` for
  environment and `server/validation.ts` for request payloads. Do not re-validate
  shapes deep inside business logic.
- Handle async errors explicitly, following the existing pattern:
  - Business logic modules use `try/catch` and return structured results
    (`{ ok: true, ... }` / `{ ok: false, error }`) or throw a typed error.
  - Express handlers are wrapped in `asyncRoute` (`server/auth.ts`) and throw
    `HttpError` (`server/validation.ts`). The single error middleware in
    `server/app.ts` maps `HttpError`, `ZodError`, Postgres `23505`, oversized bodies
    and malformed JSON to responses. Do not duplicate that mapping per route.
- Persist through `server/db.ts` helpers (`get`, `put`, `list`, `transaction`,
  `appendAudit`), not ad-hoc SQL in route files, unless a helper is genuinely
  missing.
- Authorize every non-public route with `requireAuth` + `requireRole(...)`. Roles
  are exactly `ADMIN`, `OPERATOR`, `VIEWER` (`shared/state.ts`). They must not
  diverge; do not introduce new roles.
- Keep the client contract honest: types shared by client and server live in
  `src/types/index.ts` or `shared/`, not duplicated in components.
- Keep dependencies minimal. Ask before adding a third-party package.
- Write complete, functional code. No placeholders, `TODO`s, or omitted logic
  unless the user explicitly asks for a sketch.

---

### 5. Safety Boundaries (Do Not Touch)

These rules are binding on every agent: they override convenience, and they are
not negotiable without explicit human approval.

- NEVER read, modify, or commit `.env` / `.env.production` / `.env.test` or any
  hardcoded secret. `.gitignore` excludes `.env*`; only `.env.example` is tracked.
- NEVER edit an already-applied migration in `server/migrations/`, nor any file in
  `server/migrations/retired/`. Add the next numbered file instead.
- Do not edit `dist/`, `server-dist/`, `data/`, `.runtime/`, `backups/`, or `secrets/`;
  they are generated or operator-owned.
- NEVER bypass type checking or lint rules (`@ts-ignore`, `@ts-expect-error`, `as any`,
  `eslint-disable`) without an inline explanation of why the escape is unavoidable.
- The React Hooks exhaustive-deps eslint suppressions in `ArchiveRetentionView.tsx`
  and `MlOperationsView.tsx` are deliberate; do not copy the pattern to new files.
- Ask before adding a third-party package, changing `engines.node`, or touching the
  Dockerfile or `compose.yaml` runtime shape.

### 6. Verification Workflow

Before completing any code change:

1. Run `npm run lint` and confirm zero type errors.
2. Run the relevant tests (`npm test`, or a focused file such as
   `node --import tsx --test --test-concurrency=1 tests/analytics.test.ts`). For
   database-touching work, set `TEST_DATABASE_URL` and run `npm run test:ci`; see
   *Running the Test Suite* below for the disposable-database procedure. Do not
   treat a skipped database suite as a pass.
3. Summarize modified files clearly in plain English, and mention any operator-
   visible behavior change.

---

## Focused Test Commands

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
themselves as skipped (`{ skip: !database }`) when it is absent. 34 of the 110
`tests/*.test.ts` files take the second tier, so a `npm test` without a
database passes, but it proves only the unit tier: every database-backed
test is reported as `# SKIP` and is silently unverified.

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
| `npm test` (no database) | unit tier passes; every database-backed test reported as `# SKIP` |
| `npm test` (with `TEST_DATABASE_URL`) | unit and database tiers both pass, nothing skipped |
| `npm run test:ci` (with `TEST_DATABASE_URL`) | exit 0 |

`test:ci` requires `TEST_DATABASE_URL` and fails fast without it; it does *not*
fall back to `localhost:5433`. `tests/global-setup.ts` does probe
`localhost:5433`/`127.0.0.1:5433` for the Vitest runner, but its permission to
run is governed by the same opt-in rule. If no database is reachable the two
fallbacks are skipped, so database suites are skipped too (do not treat this
as a failing suite on a machine without PostgreSQL - that is by design). If you're
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

- Rendered as one tab branch in `src/App.tsx` (`activeTab === 'action-center'`).
- Listed in the `pages` registry in `src/design/pages.ts` under the
  "Autonomous pipeline" section as "Email delivery action center".
- Reached from the "Email & Notifications" group of the sidebar in
  `src/components/Sidebar.tsx` (pages are id-based tabs; there is no URL route).

**Permissions:** Requires ADMIN or OPERATOR role for management actions

**Components:**

- Email delivery SLA metrics dashboard
- Delivery status monitoring with real-time updates
- Bulk action toolbar for selected logs
- Advanced filtering and search interface
- Email queue management with retry capabilities
- Delivery timeline and history tracking
