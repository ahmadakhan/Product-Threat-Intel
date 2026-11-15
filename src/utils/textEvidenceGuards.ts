/**
 * Guards that decide whether a free-text mention of an inventoried identity is
 * actually evidence *about that identity*.
 *
 * A text match is the weakest form of applicability evidence, and the two ways it
 * goes wrong are structural, not statistical:
 *
 *  1. **Negation.** "Windows Server 2022 is not affected" contains the vendor and
 *     product exactly as an affected advisory would. Nothing about token presence
 *     distinguishes the two, so the sentence must be read.
 *
 *  2. **Passive platform.** "a flaw in Tomcat running on Windows Server 2022"
 *     names the asset only as the substrate the vulnerable product happens to run
 *     on. Reporting it asserts exposure that the source never claimed, and on a
 *     fleet where most hosts are Windows it is the single largest source of false
 *     alerts.
 *
 * Both checks are deliberately conservative in one direction only: they can
 * suppress a finding, never create one. A suppressed mention leaves the CVE
 * available to be matched by its structured evidence (CPE/PURL) or by another
 * sentence; it does not remove the CVE from consideration.
 */

/**
 * Negation phrases, matched as whole words.
 *
 * The obvious implementation -- `text.includes(phrase)` -- is wrong in a way that
 * matters: "no impact on" is a substring of nothing useful, but a one-word phrase
 * like "unaffected" would match inside "unaffectedly", and a future short phrase
 * could land inside an unrelated word. Anchoring on word boundaries costs nothing
 * and removes the whole class.
 */
const NEGATION_PATTERNS: readonly RegExp[] = [
  /\bnot\s+(?:affected|vulnerable|impacted|exploitable|susceptible)\b/,
  /\b(?:is|are|was|were)\s+not\s+(?:affected|vulnerable|impacted|exploitable|susceptible)\b/,
  /\bunaffected\b/,
  /\bnot\s+at\s+risk\b/,
  /\bdoes\s+not\s+(?:affect|impact)\b/,
  /\bdo\s+not\s+(?:affect|impact)\b/,
  /\bno\s+impact\s+on\b/,
  /\bnot\s+exposed\b/,
  /\bwithout\s+impact\b/,
];

/**
 * Constructions that name an identity as the host, dependency or integration
 * point of something else. `{product}` is replaced with the product's own
 * word-boundary pattern, so the guard fires on the specific product the caller is
 * evaluating rather than on any product in the sentence.
 */
// Stored as strings, not regex literals: `{product}` inside a literal is parsed
// as a (lone) quantifier bracket and the module fails to load. Up to two
// intervening words are tolerated so "running on Microsoft Windows Server 2022"
// matches a product stored as `windows_server_2022`.
const PASSIVE_CONTEXT_TEMPLATES: readonly string[] = [
  String.raw`\brunning\s+on\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bruns\s+on\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\binstalled\s+on\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bhosted\s+(?:on|by)\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bdeployed\s+on\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bvia\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bwhen\s+integrated\s+with\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bused\s+(?:by|with|on)\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
  String.raw`\bshipped\s+with\s+(?:[\p{L}\p{N}.\-]+\s+){0,2}{product}`,
];

/**
 * Sentence boundaries for evidence scanning.
 *
 * A negation or platform qualifier applies within a clause, not across the whole
 * document, so the text is split before the guards run. "Acme is not affected.
 * Acme Gateway is affected." must evaluate each claim separately.
 */
const SENTENCE_SPLIT = /[.!?\n\r]+/;

export function evidenceSentences(text: string): string[] {
  return text
    .normalize('NFKC')
    .toLowerCase()
    .split(SENTENCE_SPLIT)
    .map((sentence) => sentence.trim())
    .filter(Boolean);
}

/**
 * True when a sentence asserts the opposite of exposure for the identity it
 * names. Returns false for a sentence that merely lacks negation.
 */
export function isNegatedSentence(sentence: string): boolean {
  const normalized = sentence.normalize('NFKC').toLowerCase();
  return NEGATION_PATTERNS.some((pattern) => pattern.test(normalized));
}

/**
 * Escapes a product identity into a regex fragment that fails on partial words.
 * `\b` is unusable here because product names legitimately contain `+`, `#` and
 * `.` (C++, C#, .NET), where `\b` does not fire between a word character and `+`.
 */
function productPattern(product: string): string {
  // Identities are stored CPE-style (`windows_server_2022`), while prose spells
  // them with spaces or hyphens. Both separators are accepted between words, and
  // within a word they are interchangeable with the raw form (`pan-os`).
  // Split on separators only, keeping `+`, `#` and `.` attached where they are
  // part of the name: `visual_c++` must become `visual` + `c++`, never
  // `visual` + `c` + `+` + `+`.
  const words = product
    .normalize('NFKC')
    .toLowerCase()
    .split(/[\s_\-/]+/u)
    .filter(Boolean)
    .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  if (!words.length) return '';
  const body = words.join('[\\s_\\-]+');
  // The trailing boundary must not exclude `+` or `#`: `visual c+++` contains
  // `visual c++` followed by `+`, and must not count as the same product.
  return `(?<![\\p{L}\\p{N}+])${body}(?![\\p{L}\\p{N}+#])`;
}

/**
 * True when the sentence mentions the product only in a passive role -- as the
 * operating system, host, or dependency of the thing actually being discussed.
 *
 * A sentence that names the product in a passive role but *also* carries an
 * affectedness verb about it is not suppressed: "Tomcat running on Windows Server
 * 2022 is affected in Windows Server 2022" contains contradictory framing, and the
 * caller resolves that by falling through to the other evidence rather than being
 * silently dropped here.
 */
export function isPassivePlatformMention(sentence: string, product: string): boolean {
  const normalized = sentence.normalize('NFKC').toLowerCase();
  const pattern = productPattern(product);
  if (!pattern) return false;
  return PASSIVE_CONTEXT_TEMPLATES.some((template) =>
    new RegExp(template.replace('{product}', `(${pattern})`), 'u').test(normalized),
  );
}

/**
 * True when `sentence` is usable as evidence for `product`: it mentions the
 * product and asserts something about its exposure rather than denying it or
 * naming it as a passive platform.
 */
export function sentenceSupportsExposure(sentence: string, product: string): boolean {
  return rejectionReason(sentence, product) === undefined;
}

/**
 * Why a mention was rejected, for the evidence string. Returning a reason matters:
 * a finding that is silently dropped is indistinguishable from one that was never
 * detected, and operators cannot tune a filter they cannot see.
 */
export function rejectionReason(sentence: string, product: string): 'NEGATED' | 'PASSIVE_PLATFORM' | undefined {
  if (isNegatedSentence(sentence)) return 'NEGATED';
  if (isPassivePlatformMention(sentence, product)) return 'PASSIVE_PLATFORM';
  return undefined;
}

/**
 * Evaluates a whole document for one identity, returning the reason the mention
 * must be rejected, if any.
 *
 * Scanning sentence by sentence (rather than testing the document as a whole) is
 * what keeps the guards from over-reaching: an advisory that says "Acme Gateway
 * is not affected. Older Acme Gateway 1.x builds are affected." must still match,
 * and one that says "Tomcat running on Windows Server 2022 is affected" must match
 * Tomcat while rejecting the Windows host.
 *
 * `allowBareProduct` covers the product-wide registration case, where the caller
 * has already established that naming the product alone is intended evidence. The
 * negation guard still applies; the passive-platform guard needs the product name
 * in a sentence, which that case does not require.
 */
export function textSupportsExposure(
  text: string,
  vendor: string,
  product: string,
  allowBareProduct = false,
): 'NEGATED' | 'PASSIVE_PLATFORM' | undefined {
  const requiresVendor = !allowBareProduct;
  const mentionsVendor = (sentence: string) => sentenceMentions(sentence, vendor);
  const mentionsProduct = (sentence: string) => sentenceMentions(sentence, product);

  const relevant = evidenceSentences(text).filter(
    (sentence) => mentionsProduct(sentence) && (!requiresVendor || mentionsVendor(sentence)),
  );
  // No relevant sentence at all: the caller's identity check already passed, so
  // this can only happen when punctuation splitting separated the two identities.
  // Falling back to the whole document keeps a true positive rather than losing it
  // to tokenisation.
  if (!relevant.length) return undefined;

  const reasons = relevant.map((sentence) => rejectionReason(sentence, product));
  // One sentence that positively asserts exposure is enough: the guards suppress
  // a mention, they do not veto a document.
  if (reasons.some((reason) => reason === undefined)) return undefined;
  return reasons[0];
}

/** Word-boundary mention test that supports identities containing `+`, `#`, `.`. */
export function sentenceMentions(sentence: string, identity: string): boolean {
  const words = identity
    .normalize('NFKC')
    .toLowerCase()
    .split(/[^\p{L}\p{N}+#.]+/u)
    .filter(Boolean);
  if (!words.length) return false;
  return words.every((word) => {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?<![\\p{L}\\p{N}+])${escaped}(?![\\p{L}\\p{N}+])`, 'u').test(sentence);
  });
}
