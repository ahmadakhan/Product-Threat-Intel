/**
 * Architectural dependency-direction test.
 *
 * Asserts the layering invariant from VERIFICATION-FRAMEWORK.md (ARC-0001):
 *
 *   - server/* never imports from src/components/ or src/context/.
 *   - src/utils/* imports only src/types/, shared/, src/utils/, or node built-ins.
 *   - No import cycles within src/, server/, or shared/.
 *
 * Static import-graph scan over TypeScript source so a layer violation fails the
 * suite instead of shipping silently.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const TEST_DIR = dirname(fileURLToPath(import.meta.url));
const ROOT = join(TEST_DIR, '..');
const SRC = join(ROOT, 'src');
const SERVER = join(ROOT, 'server');
const SHARED = join(ROOT, 'shared');

type Node = { file: string; imports: string[] };

const TS_EXT = /\.tsx?$/;

function readTsFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const entry of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (TS_EXT.test(entry.name)) out.push(full);
    }
  };
  walk(dir);
  return out;
}

const relativeImportRe = /^['"](\.\.?\/[^'"]*)['"]/;

function parseImports(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  const imports: string[] = [];
  for (const match of source.matchAll(
    /import\s+(?:[^'"]*\s+from\s+)?['"]([^'"]+)['"]|from\s+['"]([^'"]+)['"]/g,
  )) {
    const spec = match[1] ?? match[2];
    if (spec && !spec.startsWith('node:')) imports.push(spec);
  }
  return imports;
}

function resolveImport(file: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null; // non-relative (package); skip
  const base = join(ROOT, file);
  const dir = join(base, '..');
  const candidates = [
    join(dir, spec),
    join(dir, spec + '.ts'),
    join(dir, spec + '.tsx'),
    join(dir, spec, 'index.ts'),
    join(dir, spec, 'index.tsx'),
  ];
  for (const c of candidates) {
    try {
      // eslint-disable-next-line no-sync -- build-time graph scan only
      readFileSync(c, 'utf8');
      return c;
    } catch {
      // not present
    }
  }
  return null;
}

test('server modules never import client components or context', () => {
  const files = readTsFiles(SERVER);
  assert.ok(files.length > 0, 'expected server files to scan');
  const violations: string[] = [];
  for (const file of files) {
    const rel = file.slice(ROOT.length);
    for (const spec of parseImports(file)) {
      if (spec.startsWith('../src/components/') || spec.startsWith('../src/context/')) {
        violations.push(`${rel} imports ${spec}`);
      }
    }
  }
  assert.deepEqual(violations, [], 'server must not import client components/context:\n' + violations.join('\n'));
});

test('src/utils modules import only types, shared, or utils', () => {
  const files = readTsFiles(join(SRC, 'utils'));
  assert.ok(files.length > 0, 'expected utils files to scan');
  const violations: string[] = [];
  for (const file of files) {
    const rel = file.slice(ROOT.length);
    for (const spec of parseImports(file)) {
      const resolved = resolveImport(file, spec);
      if (!resolved) continue;
      const rRel = resolved.slice(ROOT.length);
      const ok =
        rRel.startsWith('src/types/') ||
        rRel.startsWith('shared/') ||
        rRel.startsWith('src/utils/');
      if (!ok) violations.push(`${rel} imports ${spec} (-> ${rRel})`);
    }
  }
  assert.deepEqual(violations, [], 'utils must import only types/shared/utils:\n' + violations.join('\n'));
});

test('no import cycles within src/, server/, shared/', () => {
  const files = [...readTsFiles(SRC), ...readTsFiles(SERVER), ...readTsFiles(SHARED)];
  assert.ok(files.length > 0, 'expected files to scan');
  const graph = new Map<string, Set<string>>();
  for (const file of files) {
    const rel = file.slice(ROOT.length);
    const deps = new Set<string>();
    for (const spec of parseImports(file)) {
      const resolved = resolveImport(file, spec);
      if (!resolved) continue;
      const rRel = resolved.slice(ROOT.length);
      if (rRel.startsWith('src/') || rRel.startsWith('server/') || rRel.startsWith('shared/')) {
        deps.add(rRel);
      }
    }
    graph.set(rel, deps);
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const cycles: string[] = [];

  function dfs(node: string, path: string[]) {
    if (visiting.has(node)) {
      const idx = path.indexOf(node);
      cycles.push(path.slice(idx).join(' -> '));
      return;
    }
    if (visited.has(node)) return;
    visiting.add(node);
    path.push(node);
    for (const dep of (graph.get(node) ?? [])) dfs(dep, path);
    path.pop();
    visiting.delete(node);
    visited.add(node);
  }

  for (const node of graph.keys()) dfs(node, []);
  assert.deepEqual(cycles, [], 'import cycles detected:\n' + cycles.join('\n'));
});
