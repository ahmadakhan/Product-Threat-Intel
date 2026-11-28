/**
 * CVE remediation knowledge base.
 *
 * Produces real, actionable Required Actions & Mitigation steps for each CVE
 * from the CWE identifiers already present in the normalized CVE record
 * ("from source"), with an optional internet-sourced enrichment path that
 * degrades gracefully when no network is available.
 *
 * The knowledge base maps CWE identifiers to remediation actions drawn from
 * established vendor guidance (CISA, OWASP, MITRE CWE, language-specific
 * security cheat sheets). Every entry is vendor-neutral and safe to apply
 * subject to operator change control; the advisory body explicitly tells
 * operators to confirm against current vendor guidance before acting.
 */

import type { NormalizedCVE, RemediationPlaybook } from '../types/index.ts';

/** Canonical remediation step sets keyed by CWE id. */
const CWE_REMEDIATION: Record<
  string,
  {
    immediateActions: string[];
    workarounds: string[];
    rollbackPlan: string;
    stepByStep: string[];
  }
> = {
  // Injection families
  'CWE-89': {
    immediateActions: [
      'Replace dynamic SQL with parameterized queries or prepared statements on every affected code path.',
      'Confirm the database account used by the application has least-privilege access only.',
    ],
    workarounds: [
      'Apply input sanitization on all user-controlled parameters as a compensating control while patches are tested.',
      'Deploy a web application firewall (WAF) rule set tuned to block SQL injection patterns.',
    ],
    rollbackPlan:
      'Revert to the previous application build and restore the pre-incident database configuration from backup.',
    stepByStep: [
      'Audit all database queries in the affected component for string concatenation with user input.',
      'Rewrite each query using parameterized statements or an ORM with built-in injection protection.',
      'Test parameter binding against unit and integration test suites covering valid and malicious input.',
      'Deploy through change control to staging, verify no regression, then promote to production.',
    ],
  },
  'CWE-78': {
    immediateActions: [
      'Remove direct shell command execution from affected code paths; replace with safe API calls that do not invoke a command interpreter.',
      'If shell execution cannot be removed, enforce a strict allowlist of permitted commands and arguments.',
    ],
    workarounds: [
      'Restrict network access to the affected service until the command-injection vector is eliminated.',
      'Run the affected component in a sandboxed or containerized environment with a non-privileged user and a read-only filesystem where possible.',
    ],
    rollbackPlan:
      'Roll back to the last known-good application version and restore configuration from backup.',
    stepByStep: [
      'Identify every call site that passes user-controlled data to a shell or system function.',
      'Replace each call with a language-native API or a parameterized process-invocation API that does not use a shell.',
      'Validate all remaining inputs against an allowlist of expected values.',
      'Test in staging, then deploy through change control.',
    ],
  },
  'CWE-79': {
    immediateActions: [
      'Apply context-sensitive output encoding (HTML, attribute, JavaScript, CSS, URL) to all user-supplied data rendered in browsers.',
      'Enable a strict Content Security Policy (CSP) that disallows inline scripts and unsafe-eval.',
    ],
    workarounds: [
      'Deploy a WAF rule set targeting cross-site-scripting payloads as a temporary compensating control.',
      'Sanitize user input on the server side as a defense-in-depth measure while output encoding is rolled out.',
    ],
    rollbackPlan:
      'Revert the affected frontend component to the previous build and clear any malicious stored payloads from the database.',
    stepByStep: [
      'Inventory every template and response that reflects user-controlled data back to the client.',
      'Apply output encoding appropriate to each output context (HTML body, attribute, JavaScript block, CSS, URL).',
      'Add or tighten the Content Security Policy header and monitor violation reports.',
      'Test with stored and reflected XSS payloads, then deploy through change control.',
    ],
  },
  // Input validation
  'CWE-20': {
    immediateActions: [
      'Validate all input from external sources on the server side using strict type, length, format, and range checks.',
      'Reject input that does not conform to an explicit allowlist before any business logic processes it.',
    ],
    workarounds: [
      'Add middleware-level input validation for all API endpoints as a compensating control.',
      'Restrict access to affected endpoints to trusted networks or authenticated clients only.',
    ],
    rollbackPlan: 'Roll back application code to the previous release and restore configuration from backup.',
    stepByStep: [
      'Enumerate every input entry point (HTTP parameters, headers, body, file uploads, message queues).',
      'Implement server-side validation for each entry point using an allowlist approach.',
      'Return structured 400 errors for invalid input rather than processing or echoing it.',
      'Test valid, boundary, and invalid inputs; deploy through change control.',
    ],
  },
  // Out-of-bounds memory
  'CWE-787': {
    immediateActions: [
      'Apply the vendor security update for the affected component as soon as it is tested.',
      'If no patch is available, restrict network access to the affected service to trusted sources.',
    ],
    workarounds: [
      'Enable compiler-based buffer-overflow mitigations (stack canaries, ASLR, DEP/NX) if not already active.',
      'Run the affected component under a memory-safe sandbox or with reduced privileges.',
    ],
    rollbackPlan:
      'Revert to the previous component version and validate service operation before restoring full access.',
    stepByStep: [
      'Confirm the deployed version falls within the affected range identified in the advisory.',
      'Download the vendor patch from the official advisory link.',
      'Test the patch in a non-production environment that mirrors production configuration.',
      'Deploy through change control and verify the vulnerable function is no longer reachable.',
    ],
  },
  'CWE-125': {
    immediateActions: [
      'Apply the vendor security update for the affected component.',
      'Restrict network access to the affected service until patched.',
    ],
    workarounds: [
      'Run the component in a restricted sandbox with limited memory access.',
      'Monitor for crashes or information-disclosure events indicating active exploitation.',
    ],
    rollbackPlan: 'Revert to the previous component version from backup and confirm service health.',
    stepByStep: [
      'Identify the affected component version from the advisory and inventory.',
      'Obtain and test the vendor patch in staging.',
      'Deploy through change control and confirm the out-of-bounds read path is resolved.',
    ],
  },
  // Path traversal
  'CWE-22': {
    immediateActions: [
      'Validate and canonicalize file paths before any filesystem operation; reject paths that escape the intended directory.',
      'Use indirect object references (indexes or identifiers) instead of user-supplied filenames.',
    ],
    workarounds: [
      'Run the affected service under a dedicated OS user with read-only access to directories outside the intended root.',
      'Deploy a WAF rule that blocks path-traversal sequences (.., %2e, encoded variants).',
    ],
    rollbackPlan:
      'Revert the affected application code and restore filesystem permissions from the last known-good state.',
    stepByStep: [
      'Find every code path that accepts a file path or filename from an untrusted source.',
      'Canonicalize the resolved path and verify it remains within the allowed directory tree.',
      'Reject any path that resolves outside the base directory.',
      'Test with traversal payloads and deploy through change control.',
    ],
  },
  // Authentication / authorization
  'CWE-287': {
    immediateActions: [
      'Enforce multi-factor authentication (MFA) on all affected accounts and administrative interfaces.',
      'Review and reset credentials for any account that may have been exposed.',
    ],
    workarounds: [
      'Restrict access to affected authentication endpoints to trusted networks or a VPN.',
      'Enable account lockout after a small number of failed attempts.',
    ],
    rollbackPlan:
      'Restore the previous authentication configuration and revert any credential-store changes from backup.',
    stepByStep: [
      'Inventory all authentication entry points in the affected application.',
      'Enable MFA and strong password policies for every account with access.',
      'Disable or rotate any credentials suspected of compromise.',
      'Test authentication flows after changes and deploy through change control.',
    ],
  },
  'CWE-284': {
    immediateActions: [
      'Add explicit authorization checks on every affected endpoint and resource access path.',
      'Review current role assignments and remove excessive privileges.',
    ],
    workarounds: [
      'Restrict network access to the affected application to known-trusted clients.',
      'Enable audit logging on all authorization decisions for review.',
    ],
    rollbackPlan:
      'Revert authorization-policy changes and restore the previous role configuration from backup.',
    stepByStep: [
      'Map each API endpoint and UI function to the roles that should be allowed to access it.',
      'Implement a centralized authorization check that runs before every protected operation.',
      'Test access as both authorized and unauthorized roles.',
      'Deploy through change control and monitor authorization logs.',
    ],
  },
  'CWE-285': {
    immediateActions: [
      'Verify that the authenticated user is authorized for the specific resource or action being requested.',
      'Enforce object-level authorization checks in addition to route-level checks.',
    ],
    workarounds: [
      'Disable affected endpoints temporarily if authorization cannot be enforced immediately.',
      'Log every authorization decision for audit review.',
    ],
    rollbackPlan: 'Restore the previous access-control configuration from backup.',
    stepByStep: [
      'Identify all resources and actions that lack granular authorization checks.',
      'Implement owner- or role-based checks at the data-access layer.',
      'Test horizontal and vertical privilege-escalation scenarios.',
      'Deploy through change control.',
    ],
  },
  'CWE-862': {
    immediateActions: [
      'Apply authorization checks to every endpoint that was previously accessible without them.',
      'Default to deny: require explicit permission for every action.',
    ],
    workarounds: [
      'Place the affected service behind an authentication gateway until authorization is implemented.',
      'Limit network exposure to trusted internal clients.',
    ],
    rollbackPlan: 'Restore the previous access-control state from configuration backup.',
    stepByStep: [
      'Enumerate all endpoints and functions missing authorization checks.',
      'Add a middleware or decorator that enforces authorization on each.',
      'Test with unauthorized identities to confirm access is denied.',
      'Deploy through change control.',
    ],
  },
  // Cryptography / sensitive data
  'CWE-312': {
    immediateActions: [
      'Encrypt sensitive data at rest using strong, industry-standard algorithms and key management.',
      'Remove any plaintext sensitive data from logs, backups, and configuration files.',
    ],
    workarounds: [
      'Restrict filesystem and backup access to only the service account that needs it.',
      'Mask or tokenize sensitive fields in non-production environments.',
    ],
    rollbackPlan:
      'Restore data from the pre-change backup and re-encrypt using the prior key management configuration.',
    stepByStep: [
      'Classify all sensitive data stored or logged by the affected component.',
      'Implement encryption at rest using a FIPS-validated or industry-standard cryptographic module.',
      'Rotate any exposed credentials or keys.',
      'Verify decryption works for authorized processes and deploy through change control.',
    ],
  },
  'CWE-311': {
    immediateActions: [
      'Enable TLS 1.2 or higher for all network communications involving the affected component.',
      'Disable legacy protocols (SSL, TLS 1.0, TLS 1.1) and weak cipher suites.',
    ],
    workarounds: [
      'Terminate TLS at a load balancer or ingress proxy if the application cannot be patched immediately.',
      'Restrict access to unencrypted endpoints to trusted networks only.',
    ],
    rollbackPlan:
      'Revert TLS configuration to the previous state and reissue certificates from backup if needed.',
    stepByStep: [
      'Identify every network endpoint used by the affected component.',
      'Obtain and install valid certificates from a trusted certificate authority.',
      'Configure the service to require TLS and redirect plaintext traffic.',
      'Test with a TLS scanner and deploy through change control.',
    ],
  },
  'CWE-327': {
    immediateActions: [
      'Replace custom or weak cryptographic implementations with established, peer-reviewed libraries.',
      'Remove any use of deprecated algorithms (MD5, SHA-1, DES, RC4, ECB mode).',
    ],
    workarounds: [
      'Isolate the affected component from untrusted networks until cryptography is remediated.',
      'Monitor for signs of data tampering or decryption-based attacks.',
    ],
    rollbackPlan:
      'Restore the previous cryptographic configuration and re-encrypt data with the prior scheme from backup.',
    stepByStep: [
      'Audit all cryptographic functions in the affected code for weak or custom algorithms.',
      'Replace each with a standard library implementation (AES-GCM, RSA-OAEP, ECDSA, SHA-256 or stronger).',
      'Rotate keys and re-encrypt data protected by weak algorithms.',
      'Test encryption and decryption paths, then deploy through change control.',
    ],
  },
  // Credentials
  'CWE-798': {
    immediateActions: [
      'Remove all hard-coded credentials from source code, configuration files, and container images.',
      'Rotate every credential that was ever stored in code or version control.',
    ],
    workarounds: [
      'Restrict access to repositories and images containing embedded secrets.',
      'Scan code and artifacts for secrets and block future commits that contain them.',
    ],
    rollbackPlan:
      'Restore code from a pre-secret commit and rotate credentials back to known values if rotation is not yet complete.',
    stepByStep: [
      'Run a secrets scanner across source code, configuration, CI variables, and container images.',
      'Move discovered credentials into a secrets manager or environment variables.',
      'Rotate every exposed credential and invalidate old values.',
      'Add pre-commit and CI scans to prevent recurrence; deploy through change control.',
    ],
  },
  'CWE-269': {
    immediateActions: [
      'Apply the principle of least privilege: run services and processes with only the permissions they require.',
      'Review and revoke unnecessary privileges assigned to service accounts.',
    ],
    workarounds: [
      'Run the affected component in a container or sandbox with a restricted user and capabilities.',
      'Limit network and filesystem access for the service account.',
    ],
    rollbackPlan: 'Restore the previous privilege model and service-account configuration from backup.',
    stepByStep: [
      'Document the current privileges of every service account and process tied to the component.',
      'Reduce each to the minimum needed for intended operation.',
      'Test functionality at the reduced privilege level.',
      'Deploy through change control and monitor for access-denied events.',
    ],
  },
  // Serialization / memory safety
  'CWE-502': {
    immediateActions: [
      'Avoid deserializing untrusted data; replace with a safe data format such as JSON where possible.',
      'If deserialization is required, use a library with type constraints and integrity checks, and run it in a sandbox.',
    ],
    workarounds: [
      'Restrict network access to the affected deserialization endpoint.',
      'Apply integrity checks or signatures to all serialized data before deserialization.',
    ],
    rollbackPlan:
      'Revert to the previous application version and restore serialization configuration from backup.',
    stepByStep: [
      'Identify every deserialization call site that accepts data from untrusted sources.',
      'Replace each with a safe format parser or a constrained deserializer.',
      'Add integrity verification (HMAC or signature) to serialized data.',
      'Test with malformed and malicious payloads, then deploy through change control.',
    ],
  },
  'CWE-416': {
    immediateActions: [
      'Apply the vendor security update for the affected component.',
      'If the component is custom code, recompile with memory-safety mitigations enabled.',
    ],
    workarounds: [
      'Run the component under AddressSanitizer or a similar tool in non-production to detect use-after-free.',
      'Restart the affected service on a regular schedule to reduce the exploitation window.',
    ],
    rollbackPlan: 'Roll back to the previous build from backup and confirm service health.',
    stepByStep: [
      'Locate the code path that frees memory while a reference remains outstanding.',
      'Rewrite using smart pointers, object pools, or a memory-safe language where practical.',
      'Test under memory-error detection tools.',
      'Deploy through change control.',
    ],
  },
  // XXE
  'CWE-611': {
    immediateActions: [
      'Disable external entity resolution in all XML parsers used by the affected component.',
      'Use a simpler data format such as JSON instead of XML where feasible.',
    ],
    workarounds: [
      'Restrict network access to the affected XML-processing endpoint.',
      'Apply schema validation to reject documents containing DOCTYPE declarations.',
    ],
    rollbackPlan:
      'Restore the previous XML parser configuration from backup and clear any retrieved external content.',
    stepByStep: [
      'Find every XML parser instantiation in the affected code.',
      'Configure each parser to disallow external entities and DTD processing.',
      'Test with XXE payloads to confirm entities are not resolved.',
      'Deploy through change control.',
    ],
  },
  // Resource consumption
  'CWE-400': {
    immediateActions: [
      'Add rate limiting, request timeouts, and resource quotas to the affected endpoint.',
      'Restrict access to trusted clients until controls are in place.',
    ],
    workarounds: [
      'Deploy a WAF or API gateway rule that limits request frequency per client.',
      'Monitor CPU, memory, and connection usage for signs of abuse.',
    ],
    rollbackPlan:
      'Remove rate limits and quotas added during remediation and restore the previous configuration.',
    stepByStep: [
      'Identify endpoints vulnerable to uncontrolled resource consumption.',
      'Implement per-client rate limiting, request size caps, and timeouts.',
      'Test under load to confirm legitimate traffic is not affected.',
      'Deploy through change control.',
    ],
  },
  // Default permissions
  'CWE-276': {
    immediateActions: [
      'Audit filesystem, database, and cloud resource permissions for the affected component.',
      'Apply least-privilege permissions to all resources.',
    ],
    workarounds: [
      'Restrict network access to the affected resource.',
      'Enable access logging and review for unauthorized attempts.',
    ],
    rollbackPlan: 'Restore previous permission settings from backup and re-validate access.',
    stepByStep: [
      'List every file, directory, database object, and cloud resource used by the component.',
      'Set the most restrictive permissions that still allow intended operation.',
      'Remove default accounts, keys, and permissions shipped with the product.',
      'Test access as both authorized and unauthorized users, then deploy through change control.',
    ],
  },
};

// Generic fallback when no CWE-specific guidance is available.
const GENERIC_REMEDIATION: RemediationPlaybook = {
  patchUrl: '',
  vendorAdvisoryRef: '',
  immediateActions: [
    'Confirm affected products and versions against current vendor guidance before remediation.',
    'Apply the vendor-supplied update or documented workaround through change control.',
  ],
  workarounds: [
    'Restrict network access to affected systems until the fix is validated in your environment.',
    'Monitor affected assets for exploitation attempts and review logs for indicators of compromise.',
  ],
  rollbackPlan:
    'Restore systems to the last known-good configuration from backup if remediation causes instability.',
  stepByStep: [
    'Verify which deployed versions fall within the affected range in the advisory.',
    'Obtain the vendor patch or documented fix from the official advisory.',
    'Test the fix in a non-production environment that mirrors production.',
    'Deploy through change control and confirm the vulnerability is no longer present.',
  ],
};

/** Normalize a CWE identifier to the `CWE-NNNN` form used by the knowledge base. */
function normalizeCwe(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const upper = trimmed.toUpperCase();
  return /^CWE-\d+$/.test(upper) ? upper : null;
}

/**
 * Build a RemediationPlaybook for a CVE from its CWE identifiers.
 *
 * When multiple CWEs apply, actions are merged with duplicates removed. CWE
 * ordering is not significant; higher-severity CWEs do not override lower ones
 * because every listed weakness contributes real mitigations. Unknown CWEs
 * fall back to generic, vendor-neutral guidance.
 */
export function buildCveRemediationFromCwe(cweList: string[]): RemediationPlaybook {
  const immediate: string[] = [];
  const workarounds: string[] = [];
  const steps: string[] = [];
  let rollback = GENERIC_REMEDIATION.rollbackPlan;

  const seenImmediate = new Set<string>();
  const seenWorkaround = new Set<string>();
  const seenStep = new Set<string>();

  const addUnique = (target: string[], seen: Set<string>, value: string) => {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    target.push(normalized);
  };

  let hasSpecific = false;
  for (const cwe of cweList) {
    const id = normalizeCwe(cwe);
    if (!id) continue;
    const entry = CWE_REMEDIATION[id];
    if (!entry) continue;
    hasSpecific = true;
    for (const action of entry.immediateActions) addUnique(immediate, seenImmediate, action);
    for (const action of entry.workarounds) addUnique(workarounds, seenWorkaround, action);
    for (const action of entry.stepByStep) addUnique(steps, seenStep, action);
    if (entry.rollbackPlan && entry.rollbackPlan !== GENERIC_REMEDIATION.rollbackPlan) {
      rollback = entry.rollbackPlan;
    }
  }

  if (!hasSpecific) {
    return GENERIC_REMEDIATION;
  }

  return {
    patchUrl: '',
    vendorAdvisoryRef: '',
    immediateActions: immediate.length ? immediate : GENERIC_REMEDIATION.immediateActions,
    workarounds: workarounds.length ? workarounds : GENERIC_REMEDIATION.workarounds,
    rollbackPlan: rollback || GENERIC_REMEDIATION.rollbackPlan,
    stepByStep: steps.length ? steps : GENERIC_REMEDIATION.stepByStep,
  };
}

/**
 * Build a RemediationPlaybook for a normalized CVE record.
 *
 * This is the from-source path: CWE identifiers already parsed from the NVD
 * or feed record are turned into real remediation steps without any network
 * call. Internet enrichment (below) is layered on top when available.
 */
export function buildCveRemediation(cve: NormalizedCVE): RemediationPlaybook {
  return buildCveRemediationFromCwe(cve.cwe ?? []);
}

/**
 * Internet-sourced remediation hook.
 *
 * Implementation is intentionally a no-op stub: the runtime environment may not
 * have outbound network access, and a blocking external call would delay every
 * advisory render. Operators who want live vendor guidance can wire an HTTP
 * client (NVD, CISA KEV, vendor advisory pages, OSV) into this function. It
 * must never throw; any failure returns null and the caller falls back to
 * CWE-based guidance.
 */
export async function fetchRemediationFromInternet(
  _cveId: string,
): Promise<Partial<RemediationPlaybook> | null> {
  return null;
}

/**
 * Merge multiple remediation sources into one playbook.
 *
 * Later sources take precedence for scalar fields (patchUrl, vendorAdvisoryRef,
 * rollbackPlan). Array fields are concatenated with duplicates removed.
 * `null` or `undefined` sources are skipped; a completely empty result falls
 * back to GENERIC_REMEDIATION.
 */
export function mergeRemediation(
  ...sources: Array<Partial<RemediationPlaybook> | null | undefined>
): RemediationPlaybook {
  const merged: RemediationPlaybook = {
    patchUrl: '',
    vendorAdvisoryRef: '',
    immediateActions: [],
    workarounds: [],
    rollbackPlan: GENERIC_REMEDIATION.rollbackPlan,
    stepByStep: [],
  };

  const seen = {
    immediate: new Set<string>(),
    workaround: new Set<string>(),
    step: new Set<string>(),
  };

  const push = (arr: string[], key: 'immediate' | 'workaround' | 'step') => {
    for (const item of arr) {
      const normalized = item.trim();
      if (!normalized || seen[key].has(normalized)) continue;
      seen[key].add(normalized);
      merged[
        key === 'immediate' ? 'immediateActions' : key === 'workaround' ? 'workarounds' : 'stepByStep'
      ].push(normalized);
    }
  };

  let hasContent = false;
  for (const source of sources) {
    if (!source) continue;
    hasContent = true;
    if (source.patchUrl) merged.patchUrl = source.patchUrl;
    if (source.vendorAdvisoryRef) merged.vendorAdvisoryRef = source.vendorAdvisoryRef;
    if (source.rollbackPlan) merged.rollbackPlan = source.rollbackPlan;
    if (source.immediateActions?.length) push(source.immediateActions, 'immediate');
    if (source.workarounds?.length) push(source.workarounds, 'workaround');
    if (source.stepByStep?.length) push(source.stepByStep, 'step');
  }

  if (
    !hasContent ||
    (!merged.immediateActions.length && !merged.workarounds.length && !merged.stepByStep.length)
  ) {
    return GENERIC_REMEDIATION;
  }

  if (!merged.immediateActions.length) merged.immediateActions = [...GENERIC_REMEDIATION.immediateActions];
  if (!merged.workarounds.length) merged.workarounds = [...GENERIC_REMEDIATION.workarounds];
  if (!merged.stepByStep.length) merged.stepByStep = [...GENERIC_REMEDIATION.stepByStep];

  return merged;
}

/**
 * Severity- and exploitation-aware fallback actions.
 *
 * The CWE knowledge base above covers the weaknesses NVD actually publishes, but
 * a record can legitimately arrive with no CWE (a feed that omits `weaknesses`,
 * a vendor advisory with only prose). Substituting a fixed "confirm with the
 * vendor" sentence in that case is not an action, and it made the required-
 * actions section look auto-generated even when it had not been. These entries
 * are derived from the two signals every record does carry - severity and
 * exploitation status - so the section is always a real, severity-appropriate
 * instruction set.
 */
const SEVERITY_URGENCY: Record<
  'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN',
  {
    immediateActions: string[];
    workarounds: string[];
  }
> = {
  CRITICAL: {
    immediateActions: [
      'Isolate affected systems from untrusted networks until the vendor fix is applied; treat exposure as ongoing until patched.',
      'Apply the vendor-supplied update on an emergency change, prioritising internet-facing and privileged instances first.',
    ],
    workarounds: [
      'Enable compensating network controls (deny-by-default ingress, WAF rules, or network segmentation) for the affected service.',
      'Increase logging and alerting on the affected component and review for signs of exploitation.',
    ],
  },
  HIGH: {
    immediateActions: [
      'Schedule the vendor-supplied update in the current patch cycle and prioritise internet-facing instances.',
      'Confirm which deployed versions fall inside the affected range before remediation begins.',
    ],
    workarounds: [
      'Restrict access to the affected component to trusted networks or authenticated clients meanwhile.',
      'Monitor the affected service for exploitation attempts and review logs for anomalies.',
    ],
  },
  MEDIUM: {
    immediateActions: [
      'Apply the vendor-supplied update in the normal patch cycle after testing in a non-production environment.',
      'Confirm affected versions against current inventory and record the remediation decision.',
    ],
    workarounds: ['Limit unnecessary network exposure of the affected component until it is updated.'],
  },
  LOW: {
    immediateActions: [
      'Apply the vendor-supplied update at the next scheduled maintenance window.',
      'Record the affected versions and the planned remediation date.',
    ],
    workarounds: ['Maintain standard monitoring on the affected component.'],
  },
  UNKNOWN: {
    immediateActions: [
      'Confirm the severity and affected versions from the vendor advisory before scheduling remediation.',
      'Apply the vendor-supplied update once applicability is confirmed.',
    ],
    workarounds: ['Limit network exposure of the affected component until applicability is confirmed.'],
  },
};

/** Exploitation adds a real-time instruction regardless of the CWE table. */
const EXPLOITATION_ACTIONS = {
  kev: 'The CVE is in the CISA KEV catalogue: apply the vendor fix on an emergency timeline and verify no evidence of prior exploitation.',
  exploited:
    'Active exploitation has been reported: treat the affected systems as potentially compromised and run a compromise assessment.',
};

const GENERIC_HUNT_STEP =
  'Confirm applicability by comparing the installed version against the affected range in the vendor advisory.';

/**
 * Whether a remediation playbook is effectively empty.
 *
 * Used by the advisory renderer to decide whether to generate actions. A
 * playbook counts as missing when it has no immediate action and no step-by-step
 * guidance - the two lists the message actually renders - not when it merely
 * differs from the generic text.
 */
export function remediationIsEmpty(playbook: Partial<RemediationPlaybook> | null | undefined): boolean {
  if (!playbook) return true;
  const filled = (values?: string[]) => Boolean(values?.some((value) => value.trim()));
  return !filled(playbook.immediateActions) && !filled(playbook.stepByStep);
}

/**
 * Build the Required Actions & Mitigation list for one finding.
 *
 * Source precedence, most specific first:
 *
 *  1. the remediation already attached to the CVE record (CWE-derived at
 *     ingestion, or merged from a vendor/OSV source);
 *  2. the CWE knowledge base, rebuilt from the record's own CWE list;
 *  3. severity- and exploitation-derived instructions.
 *
 * The exploitation notes and the applicability confirmation step are appended to
 * whatever tier supplied the body, so a delivered email always tells the operator
 * both what to do and how this particular record became urgent.
 *
 * Pure: no network, no clock, no mutation of the input.
 */
export function resolveRequiredActions(input: {
  remediation?: Partial<RemediationPlaybook> | null;
  cwe?: string[];
  severity?: string;
  kev?: boolean;
  exploited?: boolean;
  maxActions?: number;
}): string[] {
  const { remediation, cwe = [], severity = 'UNKNOWN', kev = false, exploited = false } = input;
  const maxActions = input.maxActions ?? 6;
  const seen = new Set<string>();
  const actions: string[] = [];
  const add = (value: string | undefined) => {
    const action = (value ?? '').trim();
    if (!action || seen.has(action) || actions.length >= maxActions) return;
    seen.add(action);
    actions.push(action);
  };

  if (!remediationIsEmpty(remediation)) {
    for (const action of remediation?.immediateActions ?? []) add(action);
    // One worked example from the step-by-step plan; the full plan stays in the
    // CVE record, and the email must stay scannable.
    add(remediation?.stepByStep?.[0]);
    for (const action of remediation?.workarounds ?? []) add(action);
  } else {
    // CWE-derived guidance is more specific than severity guidance, so it is
    // tried first even when the record's own playbook was empty.
    const fromCwe = buildCveRemediationFromCwe(cwe);
    const hasCweGuidance = cwe.some((entry) => CWE_REMEDIATION[normalizeCwe(entry) ?? ''] !== undefined);
    if (hasCweGuidance) {
      for (const action of fromCwe.immediateActions) add(action);
      for (const action of fromCwe.workarounds) add(action);
      add(fromCwe.stepByStep[0]);
    } else {
      const band = SEVERITY_URGENCY[normaliseSeverity(severity)];
      for (const action of band.immediateActions) add(action);
      for (const action of band.workarounds) add(action);
      // The step-by-step guidance is generic in this branch, so the applicability
      // check is the only step worth carrying into the message.
      add(GENERIC_HUNT_STEP);
    }
  }

  if (kev) add(EXPLOITATION_ACTIONS.kev);
  else if (exploited) add(EXPLOITATION_ACTIONS.exploited);

  return actions;
}

function normaliseSeverity(value: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN' {
  const upper = value.trim().toUpperCase();
  return upper === 'CRITICAL' || upper === 'HIGH' || upper === 'MEDIUM' || upper === 'LOW'
    ? upper
    : 'UNKNOWN';
}
