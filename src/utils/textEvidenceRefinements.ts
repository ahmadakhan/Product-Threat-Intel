import {
  evidenceSentences,
  isNegatedSentence,
  isPassivePlatformMention,
  rawEvidenceSentences,
  sentenceMentions,
  splitExposureClauses,
} from './textEvidenceGuards.ts';

const CLAUSE_SPLIT = /[;:()\[\]{}|]|[\u2013\u2014]|\s(?:but|yet|however|whereas|although|though)\s/iu;

export function evidenceClauses(sentence: string): string[] {
  return sentence
    .split(CLAUSE_SPLIT)
    .map((clause) => clause.trim())
    .filter(Boolean);
}

const ATTRIBUTION_CUES: readonly string[] = [
  'running on',
  'runs on',
  'running within',
  'installed on',
  'deployed on',
  'hosted on',
  'hosted by',
  'hosted in',
  'based on',
  'built on',
  'built with',
  'built using',
  'written in',
  'written using',
  'written with',
  'coded in',
  'developed in',
  'developed with',
  'developed using',
  'implemented in',
  'implemented using',
  'created with',
  'created using',
  'powered by',
  'packaged as',
  'shipped with',
  'bundled with',
  'used by',
  'used with',
  'used on',
  'depending on',
  'dependent on',
];

const SEPARATOR = '[\\s_.\\-]+';

function escapeFragment(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fragment(value: string): string {
  const words = value
    .normalize('NFKC')
    .toLowerCase()
    .split(/[^\p{L}\p{N}+#.]+/u)
    .filter(Boolean);
  if (!words.length) return '';
  return words.map(escapeFragment).join(SEPARATOR);
}

function mentions(sentence: string, identity: string): boolean {
  return sentenceMentions(sentence.normalize('NFKC').toLowerCase(), identity);
}

export function isAttributedRoleClause(clause: string, identity: string): boolean {
  const subject = fragment(identity);
  if (!subject) return false;
  const text = clause.normalize('NFKC').toLowerCase();
  const tail = '(?:[\\p{L}\\p{N}+#.\\-]+[\\s,]+){0,2}$';
  const cues = ATTRIBUTION_CUES.map((cue) => new RegExp(fragment(cue) + '[\\s,]+' + tail, 'u'));
  // Every occurrence is checked: a clause with no punctuation can name the
  // identity once as a headline and again as an environment ("Acme Storefront
  // checkout disclosure ... built with Acme Storefront"). Checking only the first
  // occurrence would attribute the environment mention to the headline.
  const pattern = new RegExp(subject, 'gu');
  let occurrence: RegExpExecArray | null;
  while ((occurrence = pattern.exec(text)) !== null) {
    if (occurrence[0].length === 0) pattern.lastIndex += 1;
    const before = text.slice(0, occurrence.index);
    if (cues.some((cue) => cue.test(before))) return true;
  }
  return false;
}

export function clauseRejectionReason(
  clause: string,
  product: string,
): 'NEGATED' | 'PASSIVE_PLATFORM' | undefined {
  if (isNegatedSentence(clause)) return 'NEGATED';
  if (isPassivePlatformMention(clause, product) || isAttributedRoleClause(clause, product))
    return 'PASSIVE_PLATFORM';
  return undefined;
}

export function sentenceSupportsExposure(sentence: string, product: string): boolean {
  const clauses = evidenceClauses(sentence);
  if (!clauses.length) return true;
  return clauses.some(
    (clause) => mentions(clause, product) && clauseRejectionReason(clause, product) === undefined,
  );
}

/* -------------------------------------------------------------------------- */
/* Prose attribution                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Why the prose fallback asks "is this identity the subject?" rather than "is
 * this identity a generic word?"
 *
 * A stop-list of platform, language and delivery words (PHP, Java, WordPress,
 * `plugin`, ...) is an open-ended enumeration. It catches the names that existed
 * when it was written and silently misses every framework released afterwards,
 * so the false positive it was added to fix returns under a different product
 * name. The checks below are grammar-based and vocabulary-independent: however
 * the product is named, an advisory that mentions it only as an authoring
 * environment, a dependency, or the modifier of some other noun has not said
 * that *it* is affected.
 *
 *   "a SQL injection in X allows ..."               -> X is the subject
 *   "an X plugin that allows ..."                   -> X modifies `plugin`
 *   "... via the id parameter in PHP"               -> PHP is the vehicle
 *   "an application written in PHP that allows ..." -> PHP is the language
 *   "X is based on Y"                               -> Y is the substrate
 *   "in a default configuration, Y allows ..."      -> Y is a reference point
 *   "the X Builder plugin allows ..."              -> X is part of another name
 *
 * Every check withholds evidence and never creates it, so a miss leaves the
 * advisory to its structured CPE, alias or PURL evidence - none of which this
 * module touches - and to any other sentence in the document.
 *
 * The two shapes that used to be indistinguishable are now separated without a
 * list of product names: a capitalised continuation followed by a head noun is
 * another product's name ("the X Builder plugin allows"), while a capitalised
 * continuation that runs into the predicate is the same subject with a longer
 * name ("X Data Center is vulnerable"). See `continuesProperName`.
 */

/**
 * Predicates that assert an exposure state about their subject. CVE descriptions
 * are formulaic ("allows", "is vulnerable to", "may lead to"), so a compact
 * vocabulary covers the overwhelming majority of real prose. A clause with no
 * such word is a headline or a fragment and is not treated as a claim - which is
 * why the bare names below are deliberately excluded from this set.
 */
const EXPOSURE_PREDICATES: readonly string[] = [
  'allow',
  'allows',
  'allowed',
  'allowing',
  'enable',
  'enables',
  'enabled',
  'enabling',
  'lead',
  'leads',
  'led',
  'leading',
  'result',
  'results',
  'resulted',
  'resulting',
  'cause',
  'causes',
  'caused',
  'causing',
  'permit',
  'permits',
  'permitted',
  'let',
  'lets',
  'affect',
  'affects',
  'affected',
  'affecting',
  'compromise',
  'compromised',
  'compromises',
  'compromising',
  'exploit',
  'exploits',
  'exploited',
  'exploitable',
  'exploitation',
  'bypass',
  'bypasses',
  'bypassed',
  'crash',
  'crashes',
  'crashed',
  'hang',
  'hangs',
  'fail',
  'fails',
  // Passive and copular forms: "a flaw was found in X", "X is prone to".
  'found',
  'exists',
  'exist',
  'identified',
  'observed',
  'prone',
  'susceptible',
  'insecure',
  'improper',
  'remotely',
  'unauthenticated',
  'unverified',
];

/**
 * Adjectives that assert exposure through a copula ("versions before 2.0 are
 * affected"). They are kept out of the predicate set above because they also
 * premodify a noun ("a vulnerable Acme Widget"), where they say nothing about
 * the identity's own exposure.
 */
const EXPOSURE_ADJECTIVES = new Set([
  'affected',
  'vulnerable',
  'exploitable',
  'susceptible',
  'prone',
  'exposed',
]);

/** Copulas that link a subject to an exposure adjective. */
const COPULAS = new Set(['is', 'are', 'was', 'were', 'be', 'been', 'being', 'remains', 'remain']);

/**
 * Words that are not predicates by themselves but still assert an exposure when
 * they follow the subject. Kept separate from the predicates above because many
 * of them also head a compound noun ("Acme Widget vulnerability", "Acme Widget
 * flaw") and using them as a post-position test would turn every headline into a
 * claim that the product is affected.
 */
const EXPOSURE_MARKERS: readonly string[] = [
  'vulnerable',
  'vulnerability',
  'vulnerabilities',
  'flaw',
  'flaws',
  'weakness',
  'weaknesses',
  'injection',
  'injections',
  'disclosure',
  'escalation',
  'overrun',
  'overflow',
  'traversal',
  'execution',
  'executable',
];

const EXPOSURE_VERBS = new Set(EXPOSURE_PREDICATES);
const EXPOSURE_ANY = new Set([...EXPOSURE_PREDICATES, ...EXPOSURE_MARKERS]);

/**
 * Passive forms that take an agent: "be accessed by", "be reachable by". Their
 * object is the affected party ("can be accessed by an unauthenticated
 * attacker"), so when a "by" follows, the clause exposes that object rather than
 * the grammatical subject. Remediation verbs are kept out of this set because
 * "fixed by the vendor" is not an actor in the same sense.
 */
const AGENT_TAKING_PASSIVES = new Set(['accessed', 'reachable', 'identifiable', 'triggerable']);

const REMEDIATION_CUE = /\b(?:fixed|patched|resolved|mitigated|remediated|corrected)\s+(?:in|with|by|to)\b/u;

const RELATIVE_PRONOUNS = new Set(['that', 'which', 'who', 'whom', 'whose', 'where']);

/**
 * Words that, immediately after the identity, make it a modifier of the next
 * noun ("X plugin", "X deployments"). A name followed by one of these is being
 * described as a delivery vehicle or a place, not as the vulnerable subject.
 */
const MODIFIER_HEAD_NOUNS = new Set([
  'plugin',
  'plugins',
  'module',
  'modules',
  'theme',
  'themes',
  'component',
  'components',
  'extension',
  'extensions',
  'addon',
  'addons',
  'package',
  'packages',
  'library',
  'libraries',
  'sdk',
  'sdks',
  'framework',
  'frameworks',
  'widget',
  'widgets',
  'deployment',
  'deployments',
  'installation',
  'installations',
  'instance',
  'instances',
  'application',
  'applications',
  'app',
  'apps',
  'site',
  'sites',
  'website',
  'websites',
  'stack',
  'stacks',
  'environment',
  'environments',
  'runtime',
  'runtimes',
  'build',
  'builds',
  'release',
  'releases',
  'version',
  'versions',
  'patch',
  'patches',
  'update',
  'updates',
  'configuration',
  'configurations',
  'implementation',
  'implementations',
  'integration',
  'integrations',
  'connector',
  'connectors',
]);

/**
 * The first word of a clause decides whether a prepositional phrase there is a
 * framing reference rather than a subject: "in a default configuration ...".
 * "in X allows ..." is a subject inversion and is still read as a claim.
 */
const FRAMING_CUES = new Set([
  'in',
  'on',
  'for',
  'with',
  'within',
  'under',
  'via',
  'through',
  'by',
  'inside',
  'at',
  'from',
  'after',
  'before',
  'during',
  'using',
]);

/** Determiners and adjectives that still leave the identity the phrase's head. */
const DETERMINERS = new Set([
  'a',
  'an',
  'the',
  'its',
  'their',
  'this',
  'that',
  'these',
  'those',
  'any',
  'all',
  'some',
  'default',
  'certain',
  'affected',
  'vulnerable',
  'older',
  'newer',
  'recent',
  'current',
  'latest',
  'remaining',
  'unpatched',
  'patched',
  'known',
  'supported',
  'custom',
  'bespoke',
]);

/** Pagination and boilerplate labels that carry no attribution content. */
const NON_ASSERTIVE_START = /^(?:page|p|section|item|step|figure|table|content|last\s+updated)\b/u;

const WORD_SPLIT = /[^\p{L}\p{N}+#]+/u;

function words(value: string): string[] {
  return value.normalize('NFKC').toLowerCase().split(WORD_SPLIT).filter(Boolean);
}

/** True when `word` extends the identity into a longer proper name. */
function isNameContinuation(word: string): boolean {
  return !NAME_TERMINATORS.has(word) && !EXPOSURE_ANY.has(word) && !MODIFIER_HEAD_NOUNS.has(word);
}

/**
 * The index in `clause` where a single-token mention is only the start of a
 * longer name: "Acme Corp Ferrum Builder" mentions `ferrum`, but `Ferrum
 * Builder` is a different product. Returns -1 when every mention is complete.
 *
 * Case is the discriminator, and it is read from the clause as written (callers
 * already trim it without lower-casing). A capitalised continuation is part of
 * the proper name; a lower-case one is an ordinary noun phrase, so "a flaw in
 * Acme Widget is affected" is not three product names. When the clause carries
 * no capitals at all, the check is skipped rather than guessed: refusing there
 * would turn a formatting quirk into a lost finding.
 */
function fragmentMentionIndex(clause: string, identity: string): number {
  if (words(identity).length !== 1) return -1;
  const subject = phrasePattern(identity);
  if (!subject) return -1;
  const pattern = new RegExp(`(?<![\\p{L}\\p{N}])${subject}(?![\\p{L}\\p{N}])`, 'giu');
  const hasCapitals = /\p{Lu}/u.test(clause);
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(clause)) !== null) {
    if (match[0].length === 0) pattern.lastIndex += 1;
    const rest = clause.slice(match.index + match[0].length).trimStart();
    const [nextWord] = rest.split(WORD_SPLIT).filter(Boolean);
    if (!nextWord || !isNameContinuation(nextWord.toLowerCase())) continue;
    // Only a capitalised continuation, in a clause that has capitals at all,
    // indicates another product name.
    if (!hasCapitals) continue;
    if (/^\p{Lu}/u.test(nextWord)) return match.index;
  }
  return -1;
}

/**
 * A regex for an identity phrase that accepts `_`, `-`, `.` or whitespace between
 * its words, keeping `+` and `#` attached because they distinguish real products
 * (`c++` vs `c`).
 *
 * Separators are alternatives rather than a character class followed by a
 * quantifier: a trailing quantifier turns the next space into a possessive stop
 * and breaks stateful global matching (`lastIndex` is never advanced).
 */
function phrasePattern(identity: string): string {
  return words(identity)
    .map((word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('[\\s_.\\-]+');
}

/** Tokens following `endIndex`, used to inspect what comes after a mention. */
function wordsAfter(text: string, endIndex: number): string[] {
  return words(text.slice(endIndex));
}

/**
 * Whether a predicate or exposure marker follows the mention, and the exposure
 * it states is not one of the non-exposure forms.
 *
 * `predicateOnly` is used when an exposure word would otherwise be read as part
 * of the identity's own compound noun ("Acme Widget flaw"), in which case only a
 * true predicate after it can turn the clause into a claim.
 */
function statesExposureAfter(text: string, endIndex: number, predicateOnly = false): boolean {
  const after = wordsAfter(text, endIndex);
  const matched = after.find((word) => (predicateOnly ? EXPOSURE_VERBS.has(word) : EXPOSURE_ANY.has(word)));
  if (matched) {
    // "a cloned site can be accessed by an unauthenticated attacker" names an
    // attacker as the affected party, not the subject.
    if (AGENT_TAKING_PASSIVES.has(matched) && after.includes('by')) return false;
    return true;
  }
  // "versions before 2.0 are affected": a copula directly followed by an
  // exposure adjective is a full predicate even when no verb from the list is
  // present. The adjective is only accepted in post-copular position, so the
  // premodifier in "a vulnerable Acme Widget" does not count.
  return after.some(
    (word, index) =>
      COPULAS.has(word) && index + 1 < after.length && EXPOSURE_ADJECTIVES.has(after[index + 1]),
  );
}

/**
 * True when the mention is only the first word of a longer proper name that
 * names a *different* product.
 *
 * Two shapes must be separated, and neither needs a vocabulary of product names:
 *
 *   "the Acme PHP Builder plugin allows ..."  -> PHP Builder plugin
 *   "Atlassian Confluence Data Center is vulnerable" -> Confluence Data Center
 *
 * The first is a compound whose head noun (`plugin`) is what the predicate is
 * about, so `PHP` only modifies it. The second is a subject noun phrase that the
 * predicate agrees with, so `Confluence` is inside the affected subject.
 *
 * The discriminator is therefore structural: a capitalised continuation means a
 * different product only when a delivery/head noun follows it, because that head
 * noun is then the thing the clause is about. A continuation that runs straight
 * into a predicate is the same subject with a longer name.
 *
 * Only single-token identities are checked, and only against capitalised words
 * that appear mid-sentence in the source: a sentence-initial capital is ordinary
 * orthography, and a lower-case continuation is an ordinary noun phrase.
 */
function continuesProperName(
  text: string,
  identity: string,
  endIndex: number,
  properNouns: ReadonlySet<string>,
): boolean {
  if (words(identity).length !== 1 || properNouns.size === 0) return false;
  const after = wordsAfter(text, endIndex);
  const [next] = after;
  if (!next) return false;
  if (NAME_TERMINATORS.has(next) || EXPOSURE_ANY.has(next) || DETERMINERS.has(next)) return false;
  if (!properNouns.has(next)) return false;
  // A head noun within the next two words is what the predicate belongs to; the
  // identity is then its modifier rather than the affected subject.
  return after.slice(1, 3).some((word) => MODIFIER_HEAD_NOUNS.has(word));
}

/**
 * True when the mention introduces a relative clause ("an X plugin that allows
 * file uploads"). The relative clause is part of the noun phrase the identity
 * modifies, so the exposure belongs to the compound noun, not to X itself.
 *
 * A determiner and a head noun may intervene ("the Acme Storefront plugin that
 * allows"); the head noun is what carries the relative clause. A wider window
 * would let the "for" in "Input Fields for WooCommerce plugin that allows ..."
 * look like the gap before a pronoun, turning a real subject into an attributed
 * role.
 */
function opensRelativeClauseAfter(text: string, endIndex: number): boolean {
  const after = wordsAfter(text, endIndex);
  let index = 0;
  while (index < after.length && DETERMINERS.has(after[index])) index += 1;
  if (index < after.length && MODIFIER_HEAD_NOUNS.has(after[index])) index += 1;
  // No determiner pass after the head noun: `that` is both a determiner and a
  // relative pronoun, and consuming it here would hide the clause it opens.
  return index < after.length && RELATIVE_PRONOUNS.has(after[index]);
}

/** Function words and predicates that may follow a name without extending it. */
const NAME_TERMINATORS = new Set([
  'is',
  'are',
  'was',
  'were',
  'be',
  'been',
  'being',
  'has',
  'have',
  'had',
  'can',
  'could',
  'may',
  'might',
  'will',
  'would',
  'should',
  'must',
  'that',
  'which',
  'who',
  'whom',
  'whose',
  'where',
  'when',
  'and',
  'or',
  'but',
  'with',
  'for',
  'to',
  'of',
  'in',
  'on',
  'at',
  'by',
  'from',
  'via',
  'as',
  'than',
  'allows',
  'allow',
  'affects',
  'affect',
  'contains',
  'includes',
  'uses',
  'runs',
  'version',
  'versions',
  'users',
  'user',
]);

/** True when an exposure marker (not a predicate) follows immediately. */
function afterStartsExposureMarker(text: string, endIndex: number): boolean {
  const [first] = wordsAfter(text, endIndex);
  return first !== undefined && EXPOSURE_ANY.has(first) && !EXPOSURE_VERBS.has(first);
}

/**
 * True when a finding predicate directly governs the mention through a
 * preposition: "a flaw was found in X", "a vulnerability exists in X".
 *
 * This is the periphrastic form of "a flaw in X". It must not degrade into "any
 * predicate anywhere earlier in the clause": in "... allows attackers to run
 * commands via the id parameter in PHP", PHP follows the preposition too, but the
 * word before the preposition is `parameter`, not a predicate. Requiring the
 * predicate to be the last content word before the preposition keeps the two
 * constructions apart without a vocabulary of technique nouns.
 */
function predicateGovernsMention(text: string, startIndex: number): boolean {
  const before = words(text.slice(0, startIndex));
  let preposition = -1;
  for (let index = before.length - 1; index >= 0; index -= 1) {
    if (FRAMING_CUES.has(before[index])) {
      preposition = index;
      break;
    }
  }
  if (preposition <= 0) return false;
  // The predicate must immediately precede the preposition, possibly with an
  // auxiliary between ("was found in", "may result in").
  const head = before.slice(0, preposition);
  let predicateAt = -1;
  for (let index = head.length - 1; index >= 0 && index >= head.length - 3; index -= 1) {
    if (EXPOSURE_VERBS.has(head[index])) {
      predicateAt = index;
      break;
    }
  }
  if (predicateAt === -1) return false;
  // The mention must be the preposition's object: only determiners ("a flaw was
  // found in the X") or a named instance of the identity ("... in a Zed deployment
  // instance") may follow the preposition. Anything else means the preposition
  // belongs to a deeper phrase ("... via the id parameter in PHP").
  const between = before.slice(preposition + 1);
  return between.every((word) => DETERMINERS.has(word) || MODIFIER_HEAD_NOUNS.has(word));
}

/**
 * The role the identity plays in one clause.
 *
 * `subject`      - a clause asserts exposure about it;
 * `mention`      - the clause names it only as an environment, a modifier, the
 *                  object of another verb, or inside a negated/passive clause;
 * `absent`       - the clause does not name it.
 *
 * `headline` is set by the document-level scan for the opening clause, where
 * advisory titles live. It is granted only when the document states its claim
 * elsewhere, or when there is no other text at all.
 *
 * `guards` selects which structural disqualifiers apply. The prose fallback runs
 * the product through the full set, and the vendor through a deliberately weaker
 * one: a vendor is routinely the first word of its own product name ("Acme PHP
 * Builder"), so treating that as "nested inside another name" would reject every
 * advisory whose product name begins with its vendor. The cheap vendor test is
 * only safe because the pair check below requires the product independently.
 */
export interface ClauseRoleGuards {
  /** Treat `<identity> <head noun>` as a modifier rather than a subject. */
  venue: boolean;
  /** Treat a capitalised continuation as part of a longer product name. */
  longerName: boolean;
  /** Treat a relative clause on the noun phrase as belonging to the head noun. */
  relativeClause: boolean;
}

function clauseRole(
  clause: string,
  identity: string,
  headline = false,
  guards: ClauseRoleGuards = { venue: true, longerName: true, relativeClause: true },
  properNouns: ReadonlySet<string> = new Set(),
): 'subject' | 'mention' | 'absent' {
  const text = clause.normalize('NFKC').toLowerCase();
  if (!mentions(text, identity)) return 'absent';
  if (NON_ASSERTIVE_START.test(text)) return 'mention';
  if (isNegatedSentence(clause)) return 'mention';
  if (isPassivePlatformMention(clause, identity) || isAttributedRoleClause(clause, identity))
    return 'mention';
  if (REMEDIATION_CUE.test(text)) return 'mention';

  const subject = phrasePattern(identity);
  if (!subject) return 'mention';
  const fragmentAt = guards.longerName ? fragmentMentionIndex(clause, identity) : -1;
  const pattern = new RegExp(subject, 'gu');
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    if (match[0].length === 0) pattern.lastIndex += 1;

    // The mention is only the first word of a longer product name.
    if (start === fragmentAt) continue;
    // A capitalised continuation means this is the first word of another
    // product's name ("Acme PHP Builder" mentions PHP, but the vulnerable product
    // is PHP Builder). Case is the only vocabulary-independent signal available
    // here, and it is why a new or niche framework name needs no list entry.
    if (guards.longerName && continuesProperName(text, identity, end, properNouns)) continue;
    // The mention is a modifier of a relative clause ("X plugin that allows").
    if (guards.relativeClause && opensRelativeClauseAfter(text, end)) continue;
    // A mention followed by a delivery/venue noun ("Acme Shop deployments", "a
    // plugin in X deployments", "X installations") modifies that noun instead of
    // being the subject. A relative clause on the compound is handled above. The
    // periphrastic form ("a flaw was found in a Zed deployment instance") states
    // the finding about the instance that carries the name, so it is not a venue.
    if (
      guards.venue &&
      modifiesFollowingHeadNoun(text, end, identity) &&
      !predicateGovernsMention(text, start)
    )
      continue;

    const before = words(text.slice(0, start));
    // A framing phrase at the start of the clause ("in a default configuration")
    // sets a reference point; only an inverted "in X allows ..." is a claim.
    if (before.length && FRAMING_CUES.has(before[0])) {
      const afterCue = before.slice(1).filter((word) => !DETERMINERS.has(word));
      if (!afterCue.length || afterCue.every((word) => FRAMING_CUES.has(word))) continue;
    }

    // An exposure *marker* directly after the identity is read as part of the
    // identity's own compound noun ("Acme Widget flaw"), so in that position only
    // a real predicate turns the clause into a claim. "Acme Widget flaw. ..." is
    // a headline; "Acme Widget is affected" is a claim.
    const predicateOnly = afterStartsExposureMarker(text, end);
    if (statesExposureAfter(text, end, predicateOnly)) return 'subject';
    if (predicateGovernsMention(text, start)) return 'subject';
    // A headline subject with no predicate of its own is followed by a sentence
    // that asserts the exposure ("Acme Widget vulnerability. Versions before 2.0
    // are affected."). The title is a fragment and would otherwise be discarded
    // while the body's claim is evaluated against a pronoun, losing a real
    // finding.
    //
    // The mention need not open the clause: an advisory title often names the
    // vendor before the product ("Acme Widget security advisory"). Every role that
    // would disqualify it - negation, attribution, a relative clause, a longer
    // product name - has already returned or been skipped above.
    if (headline) return 'subject';
  }
  return 'mention';
}

/**
 * The exposure role of `identity` across a document.
 *
 * `subject`   - at least one clause states exposure about it;
 * `mention`   - the document names it, but only in a role that does not assert
 *               exposure (environment, dependency, modifier, negated, passive);
 * `absent`    - the document does not name it.
 *
 * "Named but not exposed" and "not named" are different operator signals, so
 * they are reported separately rather than folded into one boolean.
 */
export function exposureRoleOf(
  text: string,
  identity: string,
  options: {
    nestedNameIsDifferentProduct?: boolean;
    /** Restrict the structural guards; see `ClauseRoleGuards`. */
    guards?: Partial<ClauseRoleGuards>;
  } = {},
): 'subject' | 'mention' | 'absent' {
  if (!text.trim() || !identity.trim()) return 'absent';
  const nestedNameIsDifferentProduct = options.nestedNameIsDifferentProduct ?? true;
  const guards: ClauseRoleGuards = {
    venue: true,
    longerName: true,
    relativeClause: true,
    ...options.guards,
  };
  const documentStatesAClaim = words(text).some((word) => EXPOSURE_VERBS.has(word));
  const sentences = evidenceSentences(text);
  // Capitalized tokens in the source, for the longer-name check. The sentence
  // splitter lower-cases, and case is the only reliable signal that separates
  // another product's name ("Ferrum Builder") from a common noun ("windows").
  const properNouns = properNounsIn(text);
  // The opening sentence, for the headline checks below.
  const context = sentences[0] ?? '';
  const clauses = sentences.flatMap((sentence) => splitExposureClauses(sentence));
  // A title-only document has no clauses other than the title itself.
  const titleOnlyDocument = clauses.length === 1;

  /**
   * Does the clause name the identity as a standalone noun phrase, rather than as
   * the modifier of a longer name ("the Acme Storefront checkout module") or of a
   * delivery noun ("Acme Storefront deployments")?
   *
   * "Acme Widget vulnerability. Versions before 2.0 are affected." gives Widget an
   * independent mention; "a SQL injection in the Acme Ferrum Builder plugin" does
   * not, because `ferrum` only ever appears as the first word of `ferrum builder`.
   */
  const namesStandaloneSubject = (clause: string): boolean => {
    if (guards.longerName && fragmentMentionIndex(clause, identity) !== -1) return false;
    const subject = phrasePattern(identity);
    if (!subject) return false;
    const text = clause.normalize('NFKC').toLowerCase();
    const match = new RegExp(subject, 'u').exec(text);
    if (!match) return false;
    const end = match.index + match[0].length;
    if (guards.venue && modifiesFollowingHeadNoun(text, end, identity)) return false;
    return !guards.relativeClause || !opensRelativeClauseAfter(text, end);
  };

  /**
   * Does this clause state a predicate about the identity, without putting it in
   * an environment/dependency/negated role?
   *
   * This is what the title check below defers to. In "Acme Widget flaw. An
   * application written in Acme Widget allows XSS", the second clause contains an
   * exposure verb (`allows`) and names the identity, but the predicate belongs to
   * `application` and the identity is the language it was written in. Requiring
   * `!isNegativeRole` after the attribution guard is what separates the two.
   *
   * The identity must also be a standalone noun phrase there. "A vulnerability in
   * the Acme Storefront checkout module allows ..." names the identity only as a
   * modifier of `checkout module`, so the body is about that module; a title must
   * not rescue it. The venue test is intentionally NOT applied here: a headline
   * may legitimately introduce "Versions before 2.0 are affected", where the body
   * names no product of its own.
   */
  const clauseClaims = (clause: string): boolean =>
    mentions(clause, identity) &&
    namesStandaloneSubject(clause) &&
    !isNegativeRole(clause, identity) &&
    words(clause).some((word) => EXPOSURE_VERBS.has(word));

  // A headline may stand in for its body, but only when the body states a claim
  // about this identity somewhere the identity is the subject. Otherwise a title
  // fragment would outvote the one sentence that actually explains whose exposure
  // it is.
  const headlineEligible = documentStatesAClaim && clauses.slice(1).some(clauseClaims);

  /**
   * Evaluates one clause, including the headline and continuation exceptions.
   *
   * A headline may only stand in for a body sentence that is *about its subject*:
   * "Acme Widget vulnerability. Versions before 2.0 are affected." The body
   * sentence there opens with a reference to the same subject. A headline is
   * never applied to a clause that merely mentions the name inside a longer noun
   * phrase ("a SQL injection in the Acme Ferrum Builder plugin"), because the
   * predicate in that clause belongs to that other product.
   */
  const evaluate = (
    clause: string,
    headline: boolean,
    continuation?: string,
  ): 'subject' | 'mention' | 'absent' => {
    const clauseText = clause.normalize('NFKC').toLowerCase();
    const subject = phrasePattern(identity);
    if (!subject || !mentions(clauseText, identity)) return 'absent';
    const match = new RegExp(subject, 'u').exec(clauseText);
    if (!match) return 'absent';
    if (headline && !namesStandaloneSubject(clause)) return 'mention';
    // A headline followed by a short claim-bearing continuation evaluates both
    // as one statement ("Acme Widget vulnerability. Versions before 2.0 are
    // affected.").
    if (continuation) return clauseRole(`${clause} ${continuation}`, identity, true, guards, properNouns);
    return clauseRole(clause, identity, headline, guards, properNouns);
  };

  let mentioned = false;
  for (let index = 0; index < clauses.length; index += 1) {
    const continuation = clauses[index + 1];
    const borrowsContinuation =
      index === 0 &&
      continuation !== undefined &&
      headlineEligible &&
      clauseClaims(continuation) &&
      namesStandaloneSubject(clauses[index]) &&
      namesStandaloneSubject(continuation) &&
      words(clauses[index]).length <= HEADLINE_CLAIM_MAX_WORDS &&
      words(continuation).length <= HEADLINE_CLAIM_MAX_WORDS;
    // A title-only advisory ("Acme Widget security advisory", no body) is a plain
    // product registration: the caller already verified the names by whole-token
    // match, and there is no separate claim whose subject could be misread. It is
    // evaluated like a headline so the subject-position, longer-name and venue
    // checks still apply.
    const titleOnly =
      titleOnlyDocument &&
      !documentStatesAClaim &&
      isAdvisoryHeadline(context) &&
      cutsAtIdentity(context, identity) &&
      !isNegativeRole(context, identity);
    const role = evaluate(
      clauses[index],
      index === 0 && (headlineEligible || titleOnly),
      borrowsContinuation ? continuation : undefined,
    );
    if (role === 'subject') return 'subject';
    if (role === 'mention') mentioned = true;
  }
  return mentioned ? 'mention' : 'absent';
}

/**
 * True when the mention is a qualifier of a following delivery/venue noun rather
 * than the subject: "Shop deployments", "the Storefront checkout module".
 *
 * The offset rules encode the one distinction grammar can make here:
 *
 *   - a single-token name immediately before the noun is a qualifier
 *     ("Shop deployments", "Storefront installations");
 *   - a multi-word name immediately before the noun is a complete product phrase
 *     ("Input Fields for WooCommerce plugin") - real products end in these words,
 *     so it keeps the claim;
 *   - a multi-word name followed by a feature word and then the noun is a
 *     qualifier ("the Storefront checkout module"), unless the intervening word is
 *     a release designator ("Windows Server 2022 21H2 builds are affected"),
 *     which states the exposure of the builds.
 */
function modifiesFollowingHeadNoun(text: string, endIndex: number, identity: string): boolean {
  const after = wordsAfter(text, endIndex).slice(0, 2);
  const headAt = after.findIndex((word) => MODIFIER_HEAD_NOUNS.has(word));
  if (headAt === -1) return false;
  if (words(identity).length === 1) return headAt === 0;
  if (headAt === 0) return false;
  return !/\d/u.test(after[0] ?? '');
}

/**
 * True when the identity begins the clause or follows only determiners/adjectives.
 *
 * A clause that reaches the identity through another noun ("applications written
 * in Acme Widget") is not about the identity, even when a headline marker appears
 * later in it. This is the subject test the headline exception relies on.
 */
function cutsAtIdentity(clause: string, identity: string): boolean {
  const subject = phrasePattern(identity);
  if (!subject) return false;
  const match = new RegExp(subject, 'u').exec(clause.normalize('NFKC').toLowerCase());
  if (!match) return false;
  // A name inside a longer one ("acme" in "acme widget") only modifies that name.
  // This matters most for vendors, which are routinely the first word of the
  // product phrase.
  if (match.index === fragmentMentionIndex(clause, identity)) return false;
  const before = words(clause.slice(0, match.index));
  if (before.length && FRAMING_CUES.has(before[0])) return false;
  return true;
}

/**
 * True when the clause explicitly puts the identity in a role a headline cannot
 * override.
 *
 * Deliberately narrower than `clauseRejectionReason`: a headline may still speak
 * for a clause that mentions the name inside a passive-platform frame ("a flaw in
 * X, reported on Windows Server 2022" is about X), but not for one that negates
 * it or names it as an environment/dependency. Attribution is the distinction
 * that matters here - "written in X" is the sentence saying X is not the subject.
 */
function isNegativeRole(clause: string, identity: string): boolean {
  return isNegatedSentence(clause) || isAttributedRoleClause(clause, identity);
}

/**
 * Words that make a bare phrase an advisory headline rather than a claim:
 * "Acme Widget security advisory", "Acme Widget vulnerability notice". A
 * title-only document in this shape is a product registration naming its subject,
 * which is what the caller already verified by whole-token match.
 */
const HEADLINE_NOUNS = new Set([
  'advisory',
  'advisories',
  'bulletin',
  'bulletin',
  'notice',
  'notification',
  'update',
  'security',
  'patch',
  'release',
  'announcement',
  'alert',
  'warning',
  'report',
  // An exposure noun is just as much a headline in a title ("Visual C++
  // vulnerability") as a claim is in a sentence; grammatically it is a bare noun
  // phrase naming its own subject.
  'vulnerability',
  'vulnerabilities',
  'flaw',
  'flaws',
  'weakness',
  'weaknesses',
  'issue',
  'issues',
  'bug',
  'bugs',
]);

/**
 * Title-cased words that appear mid-sentence in the source text.
 *
 * Only these can be a continuation of a product name. A sentence-initial capital
 * is ordinary orthography ("Widget allows uploads"), so counting it would read
 * every product that starts a clause as part of a longer name.
 */
function properNounsIn(text: string): Set<string> {
  const tokens = new Set<string>();
  for (const sentence of rawEvidenceSentences(text)) {
    const wordsInSentence = sentence.split(/[^\p{L}\p{N}+#]+/u).filter(Boolean);
    for (let index = 1; index < wordsInSentence.length; index += 1) {
      const word = wordsInSentence[index];
      if (/^\p{Lu}/u.test(word)) tokens.add(word.toLowerCase());
    }
  }
  return tokens;
}

/**
 * True when the vendor and product are two different identities rather than two
 * spellings of one name. The clause-pairing fallback needs this: for a same-token
 * identity ("php"/"php") finding the name in two sentences is one fact repeated,
 * not vendor-plus-product evidence.
 */
function vendorAndProductAreDistinct(vendor: string, product: string): boolean {
  const vendorWords = words(vendor).sort().join(' ');
  const productWords = words(product).sort().join(' ');
  return vendorWords !== '' && productWords !== '' && vendorWords !== productWords;
}

/** True when the clause reads as an advisory headline. */
function isAdvisoryHeadline(clause: string): boolean {
  return words(clause).some((word) => HEADLINE_NOUNS.has(word));
}

/** Longest fragment a headline may borrow as its claim. */
const HEADLINE_CLAIM_MAX_WORDS = 12;

export interface ProseAttribution {
  /** The product is stated as the exposed subject in some clause. */
  stated: boolean;
  /** At least one clause names the identity in any role. */
  mentioned: boolean;
}

/**
 * The prose fallback's attribution test.
 *
 * The requirement is asymmetric on purpose. The **product** must be the subject
 * of an exposure-stating clause: that is the one claim the fallback is trying to
 * read. The **vendor** only has to be named somewhere, because advisories
 * routinely put the vendor in a title or a separate clause ("Acme Corp
 * publishes a bulletin. A flaw in Widget allows ..."). Demanding that the vendor
 * also be a grammatical subject would reject those true positives without
 * removing a single false one - the false positives come from the product being
 * named in an environment role, which the product check already rejects.
 *
 * `genericIdentity` is the caller's assertion that the vendor and product carry
 * no distinguishing power on their own (a same-word identity such as
 * `php`/`php`, or a very short name). For such an identity the vendor and product
 * are the same token, so "either name is stated as exposed" is the strongest
 * test the prose can support. It does not re-enable environment mentions:
 * "written in PHP" names PHP as an attribution target regardless.
 */
/**
 * True when the product is named as a modifier of another noun at every place it
 * appears, with no predicate of its own: "the Acme Storefront checkout module",
 * "Acme Storefront deployments". Such a mention is about the module or the
 * deployment, not about Storefront.
 *
 * This is the guard a structural generic exemption needs: exempting the identity
 * from the two-name requirement must not also exempt it from the role test.
 */
function productOnlyModifiesLongerName(text: string, product: string): boolean {
  const subject = phrasePattern(product);
  if (!subject) return false;
  for (const sentence of evidenceSentences(text)) {
    for (const clause of splitExposureClauses(sentence)) {
      const clauseText = clause.normalize('NFKC').toLowerCase();
      const match = new RegExp(subject, 'u').exec(clauseText);
      if (!match) continue;
      const end = match.index + match[0].length;
      // A finding predicate that directly governs the mention ("a flaw was found in
      // a Zed deployment instance") states the exposure about the instance that
      // carries the name, so it is not a plain modifier.
      if (predicateGovernsMention(clauseText, match.index)) return false;
      if (!modifiesFollowingHeadNoun(clauseText, end, product) && !opensRelativeClauseAfter(clauseText, end))
        return false;
    }
  }
  return true;
}

export function proseAttributesExposure(
  text: string,
  vendor: string,
  product: string,
  genericIdentity = false,
): ProseAttribution {
  // The vendor is evaluated without the venue/longer-name guards. A vendor is
  // routinely the first word of its own product name ("Acme PHP Builder") and is
  // frequently written as a modifier ("Acme Storefront deployments"), so applying
  // those guards to it would reject every advisory whose product name begins with
  // its vendor. That relaxation is only safe because the product is checked with
  // the full guard set and must be independently stated below.
  const vendorRole = exposureRoleOf(text, vendor, {
    nestedNameIsDifferentProduct: false,
    guards: { venue: false, longerName: false, relativeClause: false },
  });
  const productRole = exposureRoleOf(text, product);
  if (genericIdentity) {
    // A same-token identity ("php"/"php") cannot supply two independent names,
    // so it is judged on its own. It must not be named only as the modifier of a
    // longer noun ("the Acme Storefront checkout module"); otherwise a genuine
    // subject role is enough.
    const stated =
      !productOnlyModifiesLongerName(text, product) &&
      (vendorRole === 'subject' || productRole === 'subject');
    return { stated, mentioned: vendorRole !== 'absent' || productRole !== 'absent' };
  }

  // The product must be stated as the exposed subject in some clause, and the
  // vendor must be named. The vendor may sit in a distinct clause: advisories
  // routinely put the vendor in the headline and the product in the body ("Acme
  // Corp publishes a bulletin. A flaw in Widget allows ..."), so only presence is
  // required of it. This is the whole design - the product phrase carries the
  // exposure, the vendor supplies the identity - and the structural role checks
  // above are what stop a product that is merely an environment from qualifying.
  const stated =
    productRole === 'subject' && vendorRole !== 'absent' && vendorAndProductAreDistinct(vendor, product);
  return {
    stated,
    mentioned: vendorRole !== 'absent' || productRole !== 'absent',
  };
}
