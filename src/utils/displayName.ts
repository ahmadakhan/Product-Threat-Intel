/**
 * Human display names for vendor and product identifiers.
 *
 * CPE 2.3 vendors and products are lower-case, hyphen-separated identifiers, so
 * rendering them verbatim produced headings such as `fortinet / fortimanager`.
 * This module is the single source of truth shared by the server renderer
 * (which builds the delivered email) and the Template Studio preview, so the two
 * cannot disagree about how a name is shown.
 */

/**
 * Tokens whose display form is not plain title case. Keyed by the normalised
 * token (lower-case, hyphenated) so `CURY`, `cURL` and `cury` all resolve.
 */
const DISPLAY_NAME_OVERRIDES: Record<string, string> = {
  fortinet: 'Fortinet',
  fortimanager: 'FortiManager',
  fortigate: 'FortiGate',
  fortiweb: 'FortiWeb',
  fortianalyzer: 'FortiAnalyzer',
  fortiproxy: 'FortiProxy',
  fortiadc: 'FortiADC',
  fortios: 'FortiOS',
  cisco: 'Cisco',
  ios: 'IOS',
  'ios-xe': 'IOS XE',
  'ios-xr': 'IOS XR',
  'nx-os': 'NX-OS',
  'adaptive-security-appliance': 'Adaptive Security Appliance',
  microsoft: 'Microsoft',
  'windows-10': 'Windows 10',
  'windows-11': 'Windows 11',
  'windows-server': 'Windows Server',
  'exchange-server': 'Exchange Server',
  apache: 'Apache',
  'http-server': 'HTTP Server',
  'apache-tomcat': 'Apache Tomcat',
  tomcat: 'Tomcat',
  nginx: 'NGINX',
  openssl: 'OpenSSL',
  oracle: 'Oracle',
  'mysql-server': 'MySQL Server',
  postgresql: 'PostgreSQL',
  'node-js': 'Node.js',
  curl: 'cURL',
  ivanti: 'Ivanti',
  'pulse-secure': 'Pulse Secure',
  vmware: 'VMware',
  'vcenter-server': 'vCenter Server',
  esxi: 'ESXi',
  citrix: 'Citrix',
  'citrix-adc': 'Citrix ADC',
  'net-gateway': 'NetScaler Gateway',
  netscaler: 'NetScaler',
  sonicwall: 'SonicWall',
  paloaltonetworks: 'Palo Alto Networks',
  'palo-alto-networks': 'Palo Alto Networks',
  globalprotect: 'GlobalProtect',
  'pan-os': 'PAN-OS',
  checkpoint: 'Check Point',
  sophos: 'Sophos',
  f5: 'F5',
  'big-ip': 'BIG-IP',
  juniper: 'Juniper',
  junos: 'Junos',
  atlassian: 'Atlassian',
  confluence: 'Confluence',
  jira: 'Jira',
  sap: 'SAP',
  netapp: 'NetApp',
  redhat: 'Red Hat',
  'red-hat': 'Red Hat',
  google: 'Google',
  chrome: 'Chrome',
  apple: 'Apple',
  macos: 'macOS',
  'mac-os': 'macOS',
  safari: 'Safari',
  linux: 'Linux',
  kernel: 'Kernel',
  ubuntu: 'Ubuntu',
  debian: 'Debian',
  adobe: 'Adobe',
  'acrobat-dc': 'Acrobat DC',
  reader: 'Reader',
  coldfusion: 'ColdFusion',
  wordpress: 'WordPress',
  drupal: 'Drupal',
  joomla: 'Joomla',
  zoho: 'Zoho',
  manageengine: 'ManageEngine',
  kubernetes: 'Kubernetes',
  docker: 'Docker',
  gitlab: 'GitLab',
  github: 'GitHub',
};

/** Tokens left untouched because they carry no useful name. */
const PLACEHOLDER_NAMES = new Set(['*', '-', 'unknown', 'unavailable', 'n/a', '']);

/**
 * Display form of one vendor/product token: `fortimanager` -> `FortiManager`.
 *
 * A known brand resolves through DISPLAY_NAME_OVERRIDES; anything else is
 * title-cased per hyphen/underscore/space separated word. A name the operator
 * already supplied in mixed case (`Edge Gateway`) is returned unchanged, and
 * common acronyms are upper-cased. Placeholder tokens resolve to ''.
 */
export function displayName(raw: string | undefined | null): string {
  const value = (raw ?? '').trim();
  if (PLACEHOLDER_NAMES.has(value.toLowerCase())) return '';
  const normalized = value.toLowerCase().replace(/[_\s]+/g, '-');
  const override = DISPLAY_NAME_OVERRIDES[normalized];
  if (override) return override;
  return value
    .replace(/[_\-\s]+/g, ' ')
    .split(' ')
    .map((part) => {
      if (!part) return part;
      // Keep a name that is already mixed case (the operator's own branding);
      // only repair all-lower or all-upper spellings.
      if (part !== part.toLowerCase() && part !== part.toUpperCase()) return part;
      return part.charAt(0).toUpperCase() + part.slice(1).toLowerCase();
    })
    .join(' ')
    .replace(/\bIp\b/g, 'IP')
    .replace(/\bSsl\b/g, 'SSL')
    .replace(/\bTls\b/g, 'TLS')
    .replace(/\bApi\b/g, 'API')
    .replace(/\bHttp\b/g, 'HTTP')
    .replace(/\bHttps\b/g, 'HTTPS')
    .replace(/\bXml\b/g, 'XML')
    .replace(/\bSql\b/g, 'SQL')
    .replace(/\bDns\b/g, 'DNS')
    .replace(/\bVpn\b/g, 'VPN')
    .replace(/\bAd\b/g, 'AD')
    .replace(/\bOs\b/g, 'OS')
    .replace(/\bDc\b/g, 'DC')
    .replace(/\bSdk\b/g, 'SDK')
    .replace(/\bClr\b/g, 'CLR');
}
