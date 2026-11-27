/**
 * HTML escaping for email bodies, subject lines and any other text interpolated
 * into generated markup.
 *
 * This is the single implementation. Five byte-identical copies existed across
 * `server/app.ts`, `server/emailEdits.ts`, `server/newsEmail.ts`,
 * `server/advisoryEmail.ts` and `src/utils/emailTemplate.ts`. They agreed at the
 * time, but one copy dropping a character (`'` is the usual casualty) silently
 * turns every interpolation in that module into an injection point, and nothing
 * would have failed. Everything now imports this file.
 *
 * The escape set matches OWASP's HTML-entity guidance: `&` must be replaced
 * first so the entities introduced below are not double-escaped.
 */
const ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (character) => ENTITIES[character]!);
