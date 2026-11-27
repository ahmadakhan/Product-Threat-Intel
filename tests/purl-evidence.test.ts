import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesWatchlistItem, matchPurl, purlIdentity } from '../src/utils/cpeMatcher.ts';

/**
 * PURL identity is exact: the version range, not the PURL string, decides version
 * applicability. A non-match has two very different causes, and the evidence text
 * is what an operator reads when investigating why an asset was not flagged.
 * Reporting "identifiers did not match" for a release that is simply patched sent
 * engineers looking for a spelling bug.
 */
test('a PURL identity match excluded by version range is reported as such', () => {
  const outOfRange = matchesWatchlistItem(
    [], 'lodash', 'lodash', [], 't', 'd',
    { versionEndExcluding: '4.17.20' },
    ['pkg:npm/lodash@4.17.25'], ['pkg:npm/lodash'],
  );
  assert.equal(outOfRange.matched, false);
  assert.equal(outOfRange.packageVerdict, 'VERSION_EXCLUDED');
  assert.match(outOfRange.evidence, /installed version is outside the advisory range/i);

  const differentPackage = matchesWatchlistItem(
    [], 'lodash', 'lodash', [], 't', 'd',
    { versionEndExcluding: '4.17.20' },
    ['pkg:npm/express@4.18.0'], ['pkg:npm/lodash'],
  );
  assert.equal(differentPackage.matched, false);
  assert.equal(differentPackage.packageVerdict, 'IDENTITY_MISMATCH');
  assert.match(differentPackage.evidence, /identifiers did not match/i);
});

test('PURL matching keeps npm scope, ecosystem and qualifiers distinct', () => {
  assert.equal(matchPurl('pkg:npm/lodash@4.17.19', 'pkg:npm/lodash@4.17.19'), true);
  assert.equal(matchPurl('pkg:npm/lodash@4.17.19', 'pkg:npm/lodash@4.17.20'), false, 'exact version');
  assert.equal(matchPurl('pkg:npm/lodash@4.17.20', 'pkg:npm/lodash'), true, 'versionless advisory');
  assert.equal(matchPurl('pkg:npm/@scope/name@1.0.0', 'pkg:npm/@scope/name'), true, 'scope is not a version');
  assert.equal(matchPurl('pkg:npm/@scope/name@1.0.0', 'pkg:npm/@other/name'), false);
  assert.equal(matchPurl('pkg:npm/express@4.0.0', 'pkg:gem/express'), false, 'ecosystem differs');
  assert.equal(matchPurl('pkg:npm/lodash@4.0.0?os=linux', 'pkg:npm/lodash@4.0.0'), false, 'qualifier differs');
  assert.equal(purlIdentity('pkg:npm/@scope/name@1.0.0'), 'npm/@scope/name');
});

test('an in-range PURL match is still a match', () => {
  const result = matchesWatchlistItem(
    [], 'lodash', 'lodash', [], 't', 'd',
    { versionEndExcluding: '4.17.21' },
    ['pkg:npm/lodash@4.17.20'], ['pkg:npm/lodash'],
  );
  assert.equal(result.matched, true);
  assert.equal(result.method, 'PURL_EXACT');
});
