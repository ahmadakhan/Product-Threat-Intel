/**
 * Defence-in-depth sanitizer for server-authored email HTML that the browser
 * renders through `dangerouslySetInnerHTML` (Action Center preview).
 *
 * The server escapes every feed-controlled value before it reaches an email
 * body (see `escapeHtml` in server/advisoryEmail.ts, server/delivery.ts and the
 * template compiler), but the preview pane is the one place raw HTML crosses
 * the trust boundary into the SPA. If any server-side escape regresses — or an
 * operator pastes markup into a custom body override — a script tag, an inline
 * event handler, or a `javascript:` URL would execute inside the authenticated
 * origin. This module strips exactly those vectors while leaving the
 * legitimate presentational markup (tables, inline styles, headings) intact so
 * the preview still looks like the email.
 */
const REMOVE_TAG = /\s*<\/?\s*(script|iframe|object|embed|link|meta|base|form)\b[^>]*>/gi;

/** Attributes that can execute code or fetch a remote document. */
const DANGEROUS_ATTR = /^\s*(on[a-z]+|srcdoc|formaction|xlink:href|data|action|background|dynsrc|lowsrc|poster|usemap)\s*=/i;

/** URL schemes that execute code or leave the page context. */
const DANGEROUS_SCHEME = /^\s*(?:javascript|vbscript|data|file|blob)\s*:/i;

export function sanitizeEmailHtml(html: string): string {
  if (!html) return '';
  let output = html;
  // 1. Drop script-family elements with their entire element, so content
  //    between an opening and closing tag cannot survive as text markup.
  output = output.replace(
    /<\s*(script|iframe|object|embed)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi,
    '',
  );
  // 2. Drop any remaining self-closing/unpaired dangerous tags.
  output = output.replace(REMOVE_TAG, '');
  // 3. Strip attributes that can execute code or smuggle a URL, and any
  //    attribute value carrying a dangerous scheme.
  output = output.replace(/([a-zA-Z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/g, (match, name: string, value: string) => {
    if (DANGEROUS_ATTR.test(name + '=')) return '';
    const unwrapped = value.replace(/^["']|["']$/g, '').replace(/&colon;/gi, ':');
    if (DANGEROUS_SCHEME.test(unwrapped)) return '';
    return match;
  });
  return output;
}
