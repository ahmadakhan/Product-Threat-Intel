# Verification Framework — Concrete Evidence & Formal Verification

**Project:** VulnStream-Enterprise  
**Scope:** Entire codebase (Express API server, React SPA, shared types, migrations, scripts)  
**Owner:** Engineering / Security  
**Status:** Authoritative — governs all verification gates for this repository

---

## 1. Purpose and model

This framework defines how the project produces **concrete evidence** (retainable, reproducible artifacts) and **formal verification** (mathematically or mechanically grounded guarantees) for three assurance dimensions:

1. **Functional correctness** — the system does what its specification says, for all reachable inputs and states.
2. **Security compliance** — the system enforces authentication, authorization, input boundaries, secret handling, and data-flow rules required by its threat model.
3. **Architectural integrity** — module boundaries, layering, dependency direction, and concurrency invariants hold across the whole codebase.

**Core rule:** every property claimed about the codebase must be backed by at least one concrete evidence artifact that can be regenerated from a clean checkout without operator intervention. No property is "verified" by inspection alone.

### Evidence artifact taxonomy

| Artifact | What it proves | Lifecycle |
|---|---|---|
| `tests/*.test.ts` | Functional + security unit/integration properties | committed, run on every CI |
| `server/migrations/NNN_name.sql` + `schema_migrations` | Schema evolution correctness | committed, applied via `db:migrate` |
| `REQUIRED_SCHEMA_VERSION` (server/db.ts) | Schema gate is current | committed, checked by tests/migrations.test.ts |
| Zod schemas (server/config.ts, server/validation.ts) | Input boundary conformance | committed, typechecked |
| Static-analysis / typecheck output (`tsc --noEmit`) | Absence of type errors | lint gate |
| Lint/typecheck + prettier report | Code-style + type soundness | `npm run lint` |
| Migration index DDL (`server/migrations/indexes/`) | Concurrency-safe indexing | committed, applied outside transactions |
| Traceability matrix (`docs/TRACEABILITY.csv`) | Requirement → test → code coverage | committed, reviewed per release |
| Threat model + control evidence (`docs/THREAT-MODEL.md`) | Security requirements coverage | committed, reviewed per release |
| Deterministic build artifact (`server-dist/`, `dist/`) | Reproducible deployment unit | generated, verified by verify-deployment |
| Audit log chain (`src/utils/cryptoChain.ts`) | Tamper-evident operational history | runtime-generated, verifiable |

---

## 2. Functional correctness

### 2.1 Specification layer (what "correct" means)

Every behavior must have a written spec before it is considered verified:

- **Domain requirements** live in `docs/REQUIREMENTS.md` (one numbered requirement per line, `REQ-####`).
- **API contracts** live in Zod schemas under `server/validation.ts` and shared types in `src/types/index.ts` / `shared/`.
- **Schema contract** is the SQL in `server/migrations/` plus `REQUIRED_SCHEMA_VERSION`.
- **Concurrency invariants** are documented in `AUDIT-2026-CONCURRENCY.md` and pinned by `tests/correlation-drain-guard.test.ts`.

A requirement is "verified" only when at least one test case references its `REQ-####` id and the traceability matrix records the mapping.

### 2.2 Test pyramid for this repo

| Layer | Tool | Location | Gate |
|---|---|---|---|
| Type-level | `tsc --noEmit` | whole repo | `npm run lint` (exit 0) |
| Unit (no DB) | `node:test` | `tests/*.test.ts` | `npm test` |
| Unit with DB (disposable scratch DB) | `node:test` + `TEST_DATABASE_URL` | `tests/*.test.ts` | `TEST_DATABASE_URL=... npm test` |
| Integration (docker compose) | `docker compose -f docker-compose.test.yml` | scripts + tests | `npm run test:integration` |
| End-to-end (client + API) | supertest + puppeteer-core | tests + scripts | CI pipeline |

Run the authoritative gate locally:

```bash
npm run lint
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/vulnstream_test_scratch' npm test
```

Database-backed suites register as `{ skip: !database }` when `TEST_DATABASE_URL` is absent; a skipped suite is **not** a pass. Set `VULNSTREAM_REQUIRE_TEST_DB=true` or `CI=true` to make a missing database a hard failure.

### 2.3 Property-based and regression testing

- Pin concurrency and race fixes with deterministic, stubbed-pool tests (see `tests/correlation-drain-guard.test.ts` as the model: stub the pool, record stage calls, assert no query/claim runs after cancellation).
- Every bug fix gets a regression test named `<area>-regressions.test.ts` that fails on the pre-fix code and passes on the post-fix code.
- Tests must not use `t.mock.*` if they also need to pass under vitest (the shim in `tests/node-test-compat.ts` does not implement the Node mock tracker). Prefer stub objects passed through constructors over `t.mock`.

### 2.4 Formal methods (mechanically checked)

Where the cost is justified (concurrency, access control, state transitions, schema migrations), apply one of:

1. **Refinement types / type-state encoding** in TypeScript: model protocol states as distinct types so illegal states are unrepresentable (e.g. a `ClaimedBatch` cannot be claimed twice). Prefer this over runtime asserts where possible.
2. **Decision tables / exhaustive Zod discriminated unions** for classification and matching logic, so every input variant maps to exactly one output branch. Validate exhaustiveness at runtime with a `default` branch that throws `HttpError` / asserts `unreachable`.
3. **Model checking (TLA+ / Alloy)** for the correlation drain supervisor, leadership election, and dead-letter budget. Produce a `.tla` spec under `docs/formal/` and a model-check report artifact; map each checked invariant to a `REQ-####` and a test.
4. **Theorem proving (Lean / Coq / Isabelle)** only for cryptographic components (audit log Merkle chain in `src/utils/cryptoChain.ts`) if introduced; otherwise rely on property tests + deterministic fixtures.

Formal-method artifacts are evidence only when the model is checked against a machine-readable specification and the check result is committed/reviewed.

### 2.5 Determinism and hermeticity

- Tests must be deterministic: no `Date.now()`, `Math.random()`, or wall-clock assertions without injected clocks. Use fixed seeds and stubbed time.
- No test may reach the network or a real database unless it explicitly opts in via `TEST_DATABASE_URL`.
- Tests run with `--test-concurrency=1`; do not introduce shared mutable state between test files.

---

## 3. Security compliance

### 3.1 Boundary validation (parse at the boundary, Zod 4)

All external input is validated at the entry point:

- Environment: `server/config.ts` (Zod schema; malformed values fail startup).
- HTTP payloads: `server/validation.ts` (Zod schemas; `HttpError` + `asyncRoute` wrap handlers; single error middleware in `server/app.ts` maps errors to responses).
- Never re-validate shapes deep inside business logic.

Evidence: every route handler is wrapped in `asyncRoute` and every request body/query is validated by a Zod schema before reaching logic. A test asserts this for each route (`tests/command-authorization.test.ts`, `tests/config-auth.test.ts` are models).

### 3.2 Authorization model

Roles are exactly `ADMIN`, `OPERATOR`, `VIEWER` (`shared/state.ts`). No new roles. Every non-public route is authorized with `requireAuth` + `requireRole(...)`. Management actions (bulk retry/cancel/send-now in Action Center) require ADMIN or OPERATOR.

Evidence: a route-coverage test enumerates every registered route under `/api/` and asserts each non-public route has an authorization middleware applied.

### 3.3 Secrets and credentials

- Never read/modify/commit `.env`, `.env.production`, `.env.test` or hardcoded secrets. Only `.env.example` is tracked.
- Secrets are loaded through `server/secrets.ts` / runtime privileges (`server/runtimePrivileges.ts`) and never logged.
- Tests use fixture keys only (e.g. `Buffer.alloc(32, 5).toString('base64')` in `tests/correlation-drain-guard.test.ts`).

### 3.4 Static security analysis

| Check | Tool | Gate |
|---|---|---|
| Dependency vulnerabilities | `npm audit` (via CI) | clean or risk-accepted in `docs/RISK-ACCEPTANCE.md` |
| Secret scanning | grep for `sk-`, `AKIA`, `ghp_`, `BEGIN PRIVATE KEY` in committed files | pre-commit / CI |
| Type soundness (no `any` in new code) | `tsc --noEmit` | exit 0 |
| Hardcoded URLs/secrets | repo-wide grep | CI |

Do not use `@ts-ignore`, `@ts-expect-error`, `as any`, or `eslint-disable` without an inline explanation of why the escape is unavoidable.

### 3.5 Dynamic security verification

- AuthZ matrix test: for each role × endpoint combination, assert the expected status (200 / 401 / 403).
- Input-fuzzing of Zod boundaries with invalid payloads; assert `400` and no information leakage in error bodies.
- Audit-log tamper evidence: recompute the Merkle/hash chain in `src/utils/cryptoChain.ts` on a captured log and assert chain validity.

---

## 4. Architectural integrity

### 4.1 Layering rules (from AGENTS.md §2)

```
shared/          contracts (state.ts, correlation.ts) — imported by both sides
src/types/       shared client/server domain types
src/components/  React views, one file per page/tab
src/context/     AppContext.tsx — client state + all API calls
src/design/      pages.ts, icons.tsx — page identity, titles, sidebar sections
src/engine/      pipeline, classification, matching, reconciliation
src/utils/       pure, testable helpers
server/          Express modules; routes registered in server/app.ts under /api/
server/correlation/, server/ml/ — larger subsystems, own modules
server/migrations/ NNN_name.sql (transactional), indexes/ NNN_name.sql (CONCURRENTLY)
tests/           node:test suites + fixtures + shared setup
```

- The UI has no URL router: pages are tabs (`activeTab`) rendered by `src/App.tsx`, labelled/grouped by `src/design/pages.ts` and `src/components/Sidebar.tsx`. To add a page: add entry to `pages`, branch in `App.tsx`, Sidebar item.
- No ORM: persist through `server/db.ts` helpers (`get`, `put`, `list`, `transaction`, `appendAudit`), not ad-hoc SQL in route files, unless a helper is genuinely missing.
- Single-component monolith serving SPA + API from one process; do not split packages without a strong technical reason.

### 4.2 Dependency-direction invariant

Dependencies may flow only downhill:

```
components → context → engine → utils → types/shared
server routes → server domain modules → server/db.ts → pg
tests → src + server (never reverse)
```

A dependency-graph test (`tests/` or a script) asserts:
- `server/*` never imports from `src/components/` or `src/context/`.
- `src/utils/*` imports only `src/types/`, `shared/`, or node stdlib.
- No cycles (detected by `madge`/`depcruise` if added, otherwise by a custom TS import-graph script).

Evidence: committed dependency-graph report + test that fails on violation.

### 4.3 Concurrency invariants

- The correlation drain guard: a cancelled pass takes no work; cancellation before a claim means no batch is processed; the running pass clears its own `cancelDrain` handle on exit. Pinned by `tests/correlation-drain-guard.test.ts`.
- Pool statement timeout applied through libpq options (`-c statement_timeout=...`), not the unsupported pg `statement_timeout` pool property (see `server/db.ts`).
- Locks: `proper-lockfile` used for single-process coordination; leadership via `server/leadership.ts`.

Evidence: deterministic concurrency tests run under `TEST_DATABASE_URL` and via `npm run correlation:preflight`.

### 4.4 Migration and schema governance

- Migrations are transactional SQL in `server/migrations/NNN_name.sql`; unique, gap-free numeric prefix.
- Each migration records itself: `INSERT INTO schema_migrations (version) VALUES (NNN);`.
- Index DDL on populated relations lives in `server/migrations/indexes/NNN_name.sql` as `CREATE INDEX CONCURRENTLY` outside a transaction; never inline in a migration.
- Never edit an already-applied migration or anything in `server/migrations/retired/`; add the next numbered file.
- Bump `REQUIRED_SCHEMA_VERSION` in `server/db.ts` with every new migration; `tests/migrations.test.ts` fails if it lags the newest file.
- Run migrations: `npm run db:migrate`.

---

## 5. Traceability matrix

A traceability matrix is the concrete evidence that every requirement, security control, and architectural rule is covered by tests and code, and that every test traces to a requirement.

### 5.1 Format (`docs/TRACEABILITY.csv`)

```csv
id,type,title,owner,requirement,test_file,code_file,evidence,status,verified_at
REQ-0001,functional,Advisory email delivery rate SLA,eng,REQ-0001,tests/delivery-fidelity.test.ts,server/delivery.ts,delivery-audit-regressions.test.ts,passed,2026-11-25
SEC-0001,security,All /api routes require auth,sec,SEC-0001,tests/command-authorization.test.ts,server/app.ts,route-authorization-matrix.test.ts,passed,2026-11-25
ARC-0001,architecture,No server→src/components imports,eng,ARC-0001,tests/architecture-deps.test.ts,server/app.ts,dependency-graph.json,passed,2026-11-25
```

Columns:
- `id` — `REQ-####` / `SEC-####` / `ARC-####`
- `type` — functional | security | architecture
- `title` — human-readable
- `owner` — team/person accountable
- `requirement` — source requirement id
- `test_file` — test file that evidences the property
- `code_file` — primary code file implementing it
- `evidence` — additional artifact (report, regression test, formal model)
- `status` — passed | failed | waived (waivers require security sign-off and expiry date)
- `verified_at` — ISO-8601 date of last successful verification

### 5.2 Traceability rules

1. **Every requirement has ≥1 test.** A `REQ-####` with no referencing test is unverified.
2. **Every test references ≥1 requirement.** An orphan test is removed or traced.
3. **Every security control maps to a role and endpoint.** Authorization matrix is complete for all `/api/` routes.
4. **Every architectural rule has a dependency-graph or lint rule.**
5. **Matrix is reviewed each release** and updated when requirements, tests, or code change. A release is cut only when all non-waived rows are `passed`.

### 5.3 Coverage accounting

- Statement/branch coverage is measured but is **not** the acceptance criterion; traceability (requirement → test) is the criterion.
- Dead code: any exported function/module with no test reference and no runtime caller is flagged for removal.

---

## 6. Verification gates and CI pipeline

### 6.1 Local gates (run before every commit)

```bash
npm run lint               # tsc --noEmit, exit 0
npm run test               # unit tier (node:test)
# For DB-backed work:
createdb -h 127.0.0.1 -p 5433 -U postgres vulnstream_test_scratch
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5433/vulnstream_test_scratch' npm test
dropdb -h 127.0.0.1 -p 5433 -U postgres vulnstream_test_scratch
npm run prettier -- --check <changed-files>
npm run db:migrate         # against a scratch DB, not production
```

### 6.2 CI gates

| Gate | Command | Failure meaning |
|---|---|---|
| Lint/typecheck | `npm run lint` | Type error in committed code |
| Unit tier | `npm test` | Any unit test fails |
| DB tier | `TEST_DATABASE_URL=<scratch> npm test` | Any DB-backed test fails or skips under `VULNSTREAM_REQUIRE_TEST_DB=true` |
| Integration | `npm run test:integration` | Containerized suite fails |
| Schema gate | `tests/migrations.test.ts` | `REQUIRED_SCHEMA_VERSION` lags newest migration |
| Deployment verify | `npm run deployment:verify` | Build artifact not reproducible / deploy preflight fails |

`npm run test:ci` requires `TEST_DATABASE_URL` and fails fast without it (no fallback to localhost:5433). `CI=true` is treated the same way.

### 6.3 Release gate

A release is authorized only when:
1. All CI gates pass against a clean checkout.
2. Traceability matrix: all non-waived rows `passed`, reviewed, signed off by engineering + security.
3. `REQUIRED_SCHEMA_VERSION` equals the newest migration number.
4. `docs/THREAT-MODEL.md` and `docs/RISK-ACCEPTANCE.md` are current.
5. Deterministic build (`npm run build`) succeeds and `server-dist/`, `dist/` are regenerated (never committed directly).

---

## 7. Evidence retention and audit

- All evidence artifacts (test reports, traceability matrix, threat model, risk acceptance, dependency graph, formal model reports) are committed to the repository and tagged with the release.
- Test output (TAP from `node:test`) is archived per CI run for at least one year.
- The audit-log Merkle chain (`src/utils/cryptoChain.ts`) provides tamper-evident operational evidence at runtime; its validity is re-verified by test on each run.
- Waivers to any control are recorded in `docs/RISK-ACCEPTANCE.md` with owner, expiry, and compensating control; expired waivers fail the release gate.

---

## 8. Immediate next steps for this repository

1. Create `docs/REQUIREMENTS.md` with numbered `REQ-####` entries covering delivery SLA, authorization, concurrency, and schema invariants.
2. Create `docs/TRACEABILITY.csv` seeded with existing tests (`correlation-drain-guard.test.ts`, `delivery-fidelity.test.ts`, `command-authorization.test.ts`, `migrations.test.ts`).
3. Add a route-authorization-coverage test enumerating all `/api/` routes and their required roles.
4. Add a dependency-graph test asserting the layering rules in §4.1/§4.2.
5. Add `docs/THREAT-MODEL.md` and `docs/RISK-ACCEPTANCE.md`.
6. Run `npm run lint` and `npm test` to confirm zero type errors and a green unit tier.

This framework is the single source of truth for what "verified" means in this codebase. Update it through the same pull-request process as code; changes to security or architectural rules require security sign-off.