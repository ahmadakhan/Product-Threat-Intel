# AI Page Audit Prompt — VulnStream-Enterprise Frontend Pages

You are a senior frontend security and accessibility engineer. Audit the React 19 SPA pages/views in `src/components/*.tsx` (the dashboard, findings, vulnerability search, email queue/history, action center, settings, pipeline, correlation, advisories, watchlist, etc.) plus `src/App.tsx`, `src/context/AppContext.tsx`, `src/hooks/*.ts`, and `src/utils/*.ts`.

Focus ONLY on existing pages/views. Do not report missing features. Evaluate code quality, completeness, and safety of what is implemented.

## System context

- **React 19 + Vite SPA** (`src/`), **Node.js 26 + Express API** (`server/`), **PostgreSQL 17**
- Router: tab-based SPA in `src/App.tsx` (`MainContent`); context: `src/context/AppContext.tsx`
- Health endpoints: `/live`, `/ready`, `/metrics`; API calls via `src/hooks/useCollection.ts`, `src/hooks/useApi.ts`, `src/utils/api.ts`
- Auth: opaque sessions, `__Host-` cookie prefix in production, CSRF token on mutations, `requireAuth`/`requireRole` fail-closed server-side
- Styling: Tailwind CSS v4, dark/light themes, `lucide-react` icons, `motion` animations
- HTML sink: one `dangerouslySetInnerHTML` in `ActionCenter.tsx` preview, gated by `src/utils/sanitizeEmailHtml.ts`

## Audit dimensions

### 1. Cross-site scripting (XSS) — all pages

- `dangerouslySetInnerHTML` usage: every occurrence must be preceded by server-side escaping AND a client-side sanitizer; identify the sink, the data source, and the sanitizer
- User-controlled text rendered into attributes (`href`, `src`, `on*`, `style`) — must be escaped or allow-listed
- `target="_blank"` links must include `rel="noopener noreferrer"` (or `rel="noreferrer"`)
- `new URL(...)` / `URLSearchParams` on user input — must not feed `location`, `href`, or `src`
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout(string)` — prohibited
- Markdown/rich-text rendering (email templates, advisory bodies) — must be escaped or sanitized before DOM insertion
- Severity: CRITICAL

### 2. Cross-site request forgery (CSRF) & origin — state-changing UI

- Every mutation endpoint call (POST/PUT/DELETE) must include the CSRF token (cookie → header)
- `fetchCollection`/`fetchMutation` wrappers must attach CSRF token automatically where configured
- `same-origin` requests only; cross-origin `fetch` must be explicitly justified
- `Referer`/`Origin` handling on navigation; no open redirects from `href`/`location.assign` built from query params
- Severity: CRITICAL

### 3. Authentication & session handling — all pages

- `loading || !session` → `LoginView` (fail-closed); no partial UI render before auth resolves
- `sessionExpired` → login flow redirect; 401 responses → session cleared → login
- `__Host-` cookie semantics honored client-side (path=/ secure-only in production)
- Logout clears session cookie and redirects to login; no cached sensitive data left in memory/UI
- Role gating: ADMIN/OPERATOR-only views (ActionCenter bulk ops, Settings users) must hide/disable UI for lesser roles AND fail server-side
- Severity: HIGH

### 4. Error handling & resilience — all pages

- Every `fetch`/`axios` call wrapped in try/catch with user-facing error alert; no unhandled promise rejections
- `ErrorBoundary` wraps the app; page-level error boundaries where a single page failure should not kill the whole SPA
- Loading states (`useState(false)` → true/false) for every async action; disable submit buttons in flight
- Empty states for zero results; no blank panels when data is absent
- Retry actions (email queue, findings resend) must be idempotent or guarded against double-submit
- Severity: HIGH

### 5. Data integrity — mutations

- Optimistic updates must be rolled back on failure (revert to server state)
- Confirmation dialogs for destructive actions (delete finding, cancel delivery, remove user)
- Form validation client-side (zod or equivalent strict schemas) mirroring server validation; no implicit `any` on form values
- Numeric inputs bounded; date inputs validated; file inputs (PDF advisory attachments) type/size checked
- Cursor pagination: `page`/`pageSize` must be clamped to positive ints; no negative/zero page sizes
- Severity: HIGH

### 6. Accessibility (a11y) — all pages

- Every page has a unique `<h1>`/`PageHeading` with `id`; `aria-labelledby` on `<main>`
- Skip-to-content link present (`<a href="#main-content">`)
- All form inputs have associated `<label>` or `aria-label`/`aria-labelledby`
- Buttons have accessible names; icon-only buttons use `aria-label`
- `aria-expanded`/`aria-controls` on dropdowns, modals, accordions; `aria-pressed` on toggles
- Modals trap focus, restore focus on close, close on Escape
- Color contrast meets WCAG AA in both dark and light themes (text on `zinc-900/950` vs `zinc-100/50`)
- `reduced-motion` respected (no `animate-spin`/`animate-pulse` without `motion-safe` guards)
- Severity: MEDIUM

### 7. Theme & responsive — all pages

- Dark/light theme classes consistent (`dark:`/`light:` variants on text/border/bg)
- No hard-coded `bg-white`/`text-black` that break dark theme; no hard-coded `bg-zinc-900` that break light theme
- Tables responsive (`overflow-x-auto`) on mobile (390px); no horizontal overflow
- Panels/modals stack vertically on mobile; touch targets ≥ 44px
- Severity: MEDIUM

### 8. Performance & memory — all pages

- `useEffect` event listeners/timers cleaned up in return (click-outside, resize, scroll)
- `setTimeout`/`setInterval` cleared on unmount; `AbortController`/`AbortSignal.timeout` on fetch calls
- No state updates on unmounted components (guard with `mounted` ref or AbortSignal)
- Long lists virtualized or paginated (no rendering thousands of rows)
- `useMemo`/`useCallback` only where recomputation is expensive; avoid over-memoization
- Images/icons from `lucide-react` imported per-icon (no blanket `import * as`)
- Severity: MEDIUM

### 9. Type safety — all pages

- No implicit `any`; `React.FC` typed; event handlers typed (`React.FormEvent`, `React.ChangeEvent<HTMLInputElement>`)
- `e.target.value as any` / `useState<any>` minimized; prefer discriminated unions or `zod` inference
- `zod` schemas imported from shared types where server and client models align
- `isolatedModules` compatible (no `const enum`, no `namespace` re-exports across files)
- Severity: LOW

### 10. Observability & UX — all pages

- Tooltips (`title`/`aria-describedby`) on icon buttons and status badges
- Success/error toasts after mutations (copy, resend, status change, delete)
- Relative timestamps formatted via `src/utils/dateTime.ts` (timezone-aware)
- `document.title` / page title reflects current tab
- `console.error`/`console.warn` only for genuine unexpected failures, not expected flow
- Severity: LOW

## Output format

For each finding:

- **File:** `path:line`
- **Severity:** CRITICAL/HIGH/MEDIUM/LOW
- **Category:** Security/Accessibility/Resilience/DataIntegrity/Performance/TypeSafety/UX
- **Description**
- **Impact**
- **Fix**
- **Effort:** S/M/L/XL

## Priority order

1. Security vulnerabilities (XSS, CSRF, auth bypass)
2. Data loss/corruption (mutation rollback, validation)
3. Availability/reliability (error boundaries, loading states, aborts)
4. Accessibility
5. Performance
6. Type safety
7. UX/observability

## Exclusions

- `node_modules/`, `dist/`, `server-dist/`
- Server-side routes (`server/app.ts`, `server/auth.ts`) — audited separately
- Generated migration content
- Missing features not in the codebase

## Verification commands

- `npm run lint` — `tsc --noEmit` (run before every commit)
- `npm run build:client` — Vite production build
- `npm test` — `node --import tsx --test` (all tests)
- `npm run test:unit` — `vitest run --no-coverage --reporter=verbose`

## Deliverable

Produce a final page audit report grouped by dimension with a severity count summary, then implement all CRITICAL and HIGH fixes. After implementing, run `npm run lint` and `npm run build:client` to verify no regressions.
