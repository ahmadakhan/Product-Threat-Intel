# Production-Grade Code Audit Prompt

You are a senior security engineer and code reviewer performing a comprehensive production-readiness audit of the VulnStream-Enterprise codebase. This is a vulnerability intelligence platform that aggregates CVE feeds, correlates them with CPE assets, generates advisories, and delivers notifications via email/webhooks.

## Scope

Audit the entire codebase for production readiness across these dimensions:

### 1. Security
- SQL injection: verify all database queries use parameterized queries ($1, $2, etc.)
- XSS: check all user input rendered in HTML templates is escaped
- CSRF: verify state-changing endpoints have CSRF protection
- Authentication: audit JWT/session handling, token expiry, refresh logic
- Authorization: verify role-based access controls on all endpoints
- Secrets management: ensure no hardcoded API keys, passwords, or tokens
- Input validation: check all API endpoints validate and sanitize input
- Rate limiting: verify rate limiters exist on auth, API, and webhook endpoints
- CORS: check CORS configuration is restrictive, not wildcard
- SSRF: check any URL-fetching code validates target URLs
- Path traversal: check file read/write operations for path traversal
- Dependency vulnerabilities: check package.json for known CVEs

### 2. Data Integrity & Database
- Migration safety: check all migrations are idempotent and reversible
- Transaction handling: verify critical operations use transactions
- Connection pooling: check pool size, timeout, and leak prevention
- Index coverage: verify queries have appropriate indexes
- Data validation: check constraints on critical tables
- Backup strategy: verify backup/restore procedures exist
- N+1 queries: identify queries in loops that could be batched
- Deadlocks: check for lock ordering issues

### 3. Error Handling & Resilience
- Unhandled promise rejections: check all async operations have try/catch
- Process crashes: verify global error handlers (uncaughtException, unhandledRejection)
- Graceful shutdown: verify SIGTERM/SIGINT handlers close connections
- Retry logic: check external API calls have exponential backoff
- Circuit breakers: verify feed fetching has circuit breaker pattern
- Timeout handling: check HTTP requests have timeouts
- Fallback behavior: verify graceful degradation when dependencies fail
- Error logging: verify errors are logged with context, not swallowed

### 4. Concurrency & Race Conditions
- Shared state: check for mutable globals accessed concurrently
- Locking: verify proper use of advisory locks for distributed operations
- Worker coordination: check job queue has proper deduplication
- Cache invalidation: check cache consistency under concurrent access
- Session isolation: verify user sessions don't leak data

### 5. Performance
- Memory leaks: check for unclosed connections, event listeners, timers
- Bundle size: check client bundle for unnecessary dependencies
- Query performance: identify slow queries without indexes
- Caching: verify appropriate use of caching (Redis/memory)
- Pagination: verify all list endpoints have pagination
- N+1 queries: identify in loops
- Connection leaks: check all pool.connect() have release()

### 6. Code Quality
- Type safety: check for `any` types, unsafe casts, missing types
- Dead code: identify unused exports, functions, variables
- Duplication: find copy-pasted code that should be extracted
- Complexity: identify functions with cyclomatic complexity > 10
- Magic numbers: check for unexplained constants
- Error messages: verify they're helpful and don't leak internals
- Naming: check for misleading or unclear names
- Comments: verify code is self-documenting

### 7. Testing
- Coverage: identify critical paths without tests
- Test isolation: verify tests don't depend on each other
- Mock quality: check mocks match real behavior
- Edge cases: check boundary conditions are tested
- Integration tests: verify database-backed tests work
- Flaky tests: identify tests with timing dependencies

### 8. Configuration & Deployment
- Environment variables: verify all required env vars are documented
- Default values: check defaults are safe for production
- Docker: review Dockerfile and docker-compose for security
- Health checks: verify /health and /ready endpoints exist
- Logging: verify structured logging with appropriate levels
- Metrics: check for Prometheus/metrics endpoints
- Graceful degradation: verify app starts with missing optional services

### 9. ML Subsystem (server/ml/)
- Model serialization: verify round-trip (serialize → load) works
- Fallback behavior: verify all integration functions fall back when untrained
- Training safety: verify training never overwrites active model on failure
- Quality gates: verify all gates have appropriate thresholds
- Drift detection: verify PSI and concept drift are computed correctly
- Data collection: verify cron queries match database schema
- Memory: check for memory leaks in model history buffers
- Type safety: verify no `any` casts in model code

### 10. API Design
- REST conventions: verify consistent URL patterns and HTTP methods
- Error responses: check consistent error format across endpoints
- Versioning: check API versioning strategy
- Documentation: verify OpenAPI/Swagger docs exist
- Pagination: check consistent pagination across list endpoints
- Rate limiting: verify rate limits on all public endpoints

## Output Format

For each finding, provide:
- **File**: path and line number
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: Security / Performance / Reliability / Maintainability / Testing
- **Description**: what the issue is
- **Impact**: what could happen if not fixed
- **Fix**: specific code change recommended
- **Effort**: S / M / L / XL

## Priority Order

1. Security vulnerabilities (CRITICAL/HIGH)
2. Data loss/corruption risks
3. Availability/reliability issues
4. Performance bottlenecks
5. Code quality improvements
6. Test coverage gaps

## Files to Focus On

Key files in order of importance:
1. `server/app.ts` - Main API router (2000+ lines)
2. `server/delivery.ts` - Email delivery engine
3. `server/pipeline.ts` - CVE processing pipeline
4. `server/db.ts` - Database connection and queries
5. `server/auth.ts` - Authentication logic
6. `server/ingestion.ts` - Feed ingestion
7. `server/correlation/` - CVE-CPE matching
8. `server/ml/` - ML subsystem (10 models, 17 total)
9. `src/components/` - React frontend components
10. `server/main.ts` - Server bootstrap and lifecycle

## Exclusions

- Do not report issues in `node_modules/`, `dist/`, `server-dist/`
- Do not report style/formatting issues (handled by linter)
- Do not report missing features (focus on existing code quality)
- Skip generated files (migrations with auto-generated content)