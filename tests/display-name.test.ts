import assert from 'node:assert/strict';
import test from 'node:test';
import { displayName } from '../src/utils/displayName.ts';

/**
 * Vendor and product identifiers reach the email as CPE 2.3 tokens
 * (`fortinet`, `fortimanager`) or as whatever the inventory feed supplied.
 * Rendering them raw produced headings like `fortinet / fortimanager`, so the
 * shared `displayName` helper normalises them for both the delivered email and
 * the Studio preview.
 */
test('known brands render with their proper capitalisation', () => {
  const cases: Array<[string, string]> = [
    ['fortinet', 'Fortinet'],
    ['fortimanager', 'FortiManager'],
    ['fortigate', 'FortiGate'],
    ['paloaltonetworks', 'Palo Alto Networks'],
    ['big-ip', 'BIG-IP'],
    ['ios', 'IOS'],
    ['ios_xe', 'IOS XE'],
    ['adobe', 'Adobe'],
    ['curl', 'cURL'],
    ['vmware', 'VMware'],
    ['nginx', 'NGINX'],
  ];
  for (const [input, expected] of cases) assert.equal(displayName(input), expected, input);
});

test('unknown tokens are title-cased per word', () => {
  assert.equal(displayName('some-product'), 'Some Product');
  assert.equal(displayName('acme_widget_server'), 'Acme Widget Server');
  assert.equal(displayName('WIDGET'), 'Widget');
  // Common acronyms inside an otherwise plain name stay upper case.
  assert.equal(displayName('ip-camera'), 'IP Camera');
  assert.equal(displayName('ssl-vpn'), 'SSL VPN');
});

test('a name already in mixed case is preserved verbatim', () => {
  // The operator's own branding must not be mangled by title-casing.
  assert.equal(displayName('Edge Gateway'), 'Edge Gateway');
  assert.equal(displayName('iOS App'), 'iOS App');
});

test('placeholder tokens resolve to an empty name', () => {
  for (const value of ['', '   ', '*', '-', 'unknown', 'Unavailable', 'n/a', undefined, null])
    assert.equal(displayName(value), '', JSON.stringify(value));
});
