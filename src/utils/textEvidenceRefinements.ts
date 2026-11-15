import { isNegatedSentence, isPassivePlatformMention, sentenceMentions } from './textEvidenceGuards.ts';

const CLAUSE_SPLIT = /[;:()\[\]{}|]|[\u2013\u2014]|\s(?:but|yet|however|whereas|although|though)\s/iu;

export function evidenceClauses(sentence: string): string[] {
  return sentence.split(CLAUSE_SPLIT).map((clause) => clause.trim()).filter(Boolean);
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
  'shipped with',
  'bundled with',
  'used by',
  'used with',
  'depending on',
  'dependent on',
];

const SEPARATOR = '[\\s_.\\-]+';

function escapeFragment(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fragment(value: string): string {
  const words = value.normalize('NFKC').toLowerCase().split(/[^\p{L}\p{N}+#.]+/u).filter(Boolean);
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
  const at = new RegExp(subject, 'u').exec(text);
  if (!at) return false;
  const before = text.slice(0, at.index);
  const tail = '(?:[\\p{L}\\p{N}+#.\\-]+[\\s,]+){0,2}$';
  return ATTRIBUTION_CUES.some((cue) => new RegExp(fragment(cue) + '[\\s,]+' + tail, 'u').test(before));
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
