/**
 * Route authorization coverage test.
 *
 * Asserts the two authorization invariants from VERIFICATION-FRAMEWORK.md:
 *
 *   SEC-0001: every route registered under /api is authenticated (via the
 *   global `requireAuth` mount at server/app.ts:997, or inline for routes
 *   registered before the mount).
 *   SEC-0002: every authenticated /api route carries at least one
 *   `requireRole(...)` using only ADMIN / OPERATOR / VIEWER.
 *
 * Public auth-adjacent routes (/api/login, /api/password-reset/*) are exempt:
 * they are intentionally unauthenticated.
 *
 * Routes registered before the global mount are not covered by it, so each such
 * non-public route must apply requireAuth + requireRole inline
 * (e.g. /api/system-uptime).
 *
 * This is a static source scan, mirroring the pattern in
 * tests/command-authorization.test.ts, so drift between route registration and
 * authorization middleware fails the suite instead of shipping silently.
 *
 * Route regions are delimited by consecutive `app.METHOD(/api...)` registrations,
 * so middleware lookup does not depend on fragile paren-balancing inside handler
 * bodies (which may contain strings, template literals, or comments).
 */

import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const APP_PATH = new URL('../server/app.ts', import.meta.url);
const source = readFileSync(APP_PATH, 'utf8');

/** Routes that are intentionally unauthenticated (no requireAuth, no requireRole). */
const PUBLIC_ROUTES = new Set([
  '/api/login',
  '/api/password-reset/request',
  '/api/password-reset/verify',
  '/api/password-reset/complete',
]);

const ROLE_SET = new Set(['ADMIN', 'OPERATOR', 'VIEWER']);

const mountMatch = source.match(/app\.use\(\s*['"]\/api['"]\s*,\s*requireAuth\(/);
assert.ok(mountMatch, 'expected app.use("/api", requireAuth(...)) global authentication mount');
const mountIndex = mountMatch.index!;

/**
 * Collect every route registration call: its start index and the route path
 * string literal, sorted by start index.
 */
const routeRegex = /app\.(get|post|patch|put|delete)\(\s*['"](\/api[^'"]*)['"]/g;
const calls: Array<{ start: number; route: string }> = [];
let match: RegExpExecArray | null;
while ((match = routeRegex.exec(source)) !== null) {
  calls.push({ start: match.index, route: match[2] });
}
assert.ok(calls.length > 0, 'expected at least one /api route registration');
calls.sort((a, b) => a.start - b.start);

/**
 * Source region belonging to this route's registration: from its `app.METHOD(`
 * start up to (but not including) the next route registration, or end of file.
 */
function regionFor(index: number): string {
  const next = calls[index + 1]?.start ?? source.length;
  return source.slice(calls[index].start, next);
}

test('every non-public /api route is authenticated', () => {
  const violations: string[] = [];
  calls.forEach((call, i) => {
    if (PUBLIC_ROUTES.has(call.route)) return;
    // Post-mount routes are covered by the global requireAuth mount.
    if (call.start > mountIndex) return;
    // Pre-mount non-public routes must apply requireAuth inline.
    if (!/requireAuth\(/.test(regionFor(i))) {
      violations.push(`pre-mount route ${call.route} must apply requireAuth inline`);
    }
  });
  assert.deepEqual(violations, [], 'authentication violations:\n' + violations.join('\n'));
});

test('every non-public /api route has an explicit requireRole(...) middleware', () => {
  const violations: string[] = [];
  calls.forEach((call, i) => {
    if (PUBLIC_ROUTES.has(call.route)) return;
    const region = regionFor(i);
    if (!/requireRole\(/.test(region)) {
      violations.push(`route ${call.route} has no requireRole(...) middleware`);
      return;
    }
    for (const roleMatch of region.matchAll(/requireRole\(([^)]*)\)/g)) {
      const args = roleMatch[1];
      const roles = args
        .split(',')
        .map((s) => s.replace(/['"]/g, '').trim())
        .filter(Boolean);
      if (roles.length === 0) {
        violations.push(`requireRole for ${call.route} lists no role`);
        continue;
      }
      for (const role of roles) {
        if (!ROLE_SET.has(role)) {
          violations.push(
            `route ${call.route} uses invalid role ${role}; must be one of ADMIN, OPERATOR, VIEWER`,
          );
        }
      }
    }
  });
  assert.deepEqual(violations, [], 'authorization violations:\n' + violations.join('\n'));
});

test('requireRole never accepts a role outside ADMIN / OPERATOR / VIEWER', () => {
  const roleSet = new Set<string>();
  for (const match of source.matchAll(/requireRole\(([^)]*)\)/g)) {
    for (const role of match[1].split(',').map((s) => s.replace(/['"]/g, '').trim()).filter(Boolean)) {
      roleSet.add(role);
    }
  }
  assert.ok(roleSet.size > 0, 'expected at least one requireRole call');
  for (const role of roleSet) {
    assert.ok(ROLE_SET.has(role), `unauthorized role ${role} used in requireRole`);
  }
  assert.deepEqual([...roleSet].sort(), ['ADMIN', 'OPERATOR', 'VIEWER'].sort());
});
