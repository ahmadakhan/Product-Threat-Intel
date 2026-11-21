export type EmailTemplateContext = Record<string, unknown> | string | number | boolean | null;

type Node =
	| { type: 'text'; value: string }
	| { type: 'value'; key: string; raw: boolean }
	| { type: 'if'; key: string; yes: Node[]; no: Node[] }
	| { type: 'each'; key: string; children: Node[] };

interface RenderOptions {
	preserveUnknown?: boolean;
	rawHtmlKeys?: ReadonlySet<string>;
}

/**
 * Deepest `{{#if}}` / `{{#each}}` nesting the renderer will build a tree for.
 *
 * Parsing and rendering are recursive, so nesting is JS stack depth and a
 * template is operator-supplied (up to 200,000 characters in the advisory
 * Studio). A few thousand nested blocks used to escape as a raw
 * `RangeError: Maximum call stack size exceeded`; the cap turns that into a
 * one-line message an operator can act on, rejected before any output exists.
 */
export const MAX_TEMPLATE_BLOCK_DEPTH = 100;

/**
 * Anchored shapes of a single token, applied to the text between one `{{` and
 * the next `}}`. The closing brace is mandatory by construction: a stray `{{`
 * (a template mid-edit, CVE prose containing braces) simply never matches, so
 * it costs one scan instead of the quadratic backtracking the previous
 * unanchored pattern produced (50,000 stray braces took ~25s on the request
 * thread). A triple-brace token must end in `}}}`.
 */
const PLAIN_TOKEN = /^\{\{\s*(?:#if\s+[^}\s]+|#each\s+[^}\s]+|\/[a-z]+|else|[^}]+?)\s*\}\}$/;
const RAW_TOKEN = /^\{\{\{\s*([^}]+?)\s*\}\}\}$/;

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (char) => ({
		'&': '&amp;',
		'<': '&lt;',
		'>': '&gt;',
		'"': '&quot;',
		"'": '&#39;',
	})[char]!);
}

function parse(template: string): Node[] {
	// Tokenise first, then build the tree iteratively. Scanning and building in
	// one pass was quadratic: every `exec()` restart at a tag the grammar did not
	// recognise re-scanned the whole remaining template, so a 200,000-character
	// body of stray `{{` took tens of seconds inside the HTTP request. A single
	// tokenise pass makes the work linear, and the explicit frame stack makes
	// nesting depth bounded by the parser rather than by the JS call stack.
	const tokens: Array<{ index: number; end: number; value: string; raw: boolean }> = [];
	// Walk candidate openers left to right. Each candidate is the text from one
	// `{{` to the next `}}`; both anchored shapes require that closing pair, so
	// the scanner never resumes before the previous match (no backtracking) and
	// text without a closing brace is skipped in a single pass.
	let open = template.indexOf('{{');
	while (open !== -1) {
		// A triple-brace token ends on `}}}`, everything else on `}}`. Taking the
		// first `}}` for `{{{name}}}` left one `}` inside the value.
		const close = template.startsWith('{{{', open)
			? template.indexOf('}}}', open + 3)
			: template.indexOf('}}', open + 2);
		if (close === -1) break;
		const end = close + (template.startsWith('{{{', open) ? 3 : 2);
		const candidate = template.slice(open, end);
		const raw = RAW_TOKEN.exec(candidate);
		if (raw) tokens.push({ index: open, end, value: raw[1].trim(), raw: true });
		else if (PLAIN_TOKEN.test(candidate))
			tokens.push({ index: open, end, value: candidate.slice(2, -2).trim(), raw: false });
		open = template.indexOf('{{', end);
	}

	const root: Node[] = [];
	const frames: Array<{
		kind: 'if' | 'each';
		key: string;
		nodes: Node[];
		yes?: Node[];
		inElse?: boolean;
	}> = [];
	const target = () => (frames.length ? frames[frames.length - 1].nodes : root);
	const append = (node: Node) => target().push(node);
	let cursor = 0;

	for (const token of tokens) {
		if (token.index > cursor) append({ type: 'text', value: template.slice(cursor, token.index) });
		cursor = token.end;
		const frame = frames[frames.length - 1];

		// Block keywords are case-insensitive, like the `#if x` / `#each x` openers
		// matched below, so {{ELSE}} and {{/IF}} close the block they started.
		const keyword = token.value.toLowerCase();
		if (keyword === 'else') {
			if (!frame || frame.kind !== 'if' || frame.inElse) continue;
			frame.yes = frame.nodes;
			frame.nodes = [];
			frame.inElse = true;
			continue;
		}
		if (keyword === '/if' || keyword === '/each') {
			const kind = keyword.slice(1) as 'if' | 'each';
			// A close tag that does not match the open block is ignored, matching
			// the previous behaviour of skipping unrecognised tokens.
			if (!frame || frame.kind !== kind) continue;
			frames.pop();
			const node: Node =
				kind === 'if'
					? { type: 'if', key: frame.key, yes: frame.yes ?? frame.nodes, no: frame.inElse ? frame.nodes : [] }
					: { type: 'each', key: frame.key, children: frame.nodes };
			append(node);
			continue;
		}
		const block = /^#(if|each)\s+([a-z_][a-z0-9_]*)$/i.exec(token.value);
		if (block) {
			if (frames.length >= MAX_TEMPLATE_BLOCK_DEPTH)
				throw new Error(
					`Template blocks nest deeper than ${MAX_TEMPLATE_BLOCK_DEPTH} levels; flatten the template`,
				);
			frames.push({ kind: block[1].toLowerCase() as 'if' | 'each', key: block[2], nodes: [] });
			continue;
		}
		if (token.value.startsWith('#') || token.value.startsWith('/')) continue;
		// `{{}}` names nothing. Rendering it re-emits the literal braces, which is
		// not a placeholder and would be handed to the recipient as text.
		if (!token.value) continue;
		append({ type: 'value', key: token.value, raw: token.raw });
	}
	if (cursor < template.length) append({ type: 'text', value: template.slice(cursor) });

	if (frames.length) {
		const unclosed = frames[frames.length - 1];
		throw new Error(`Unclosed {{#${unclosed.kind}}} block`);
	}
	return root;
}

function lookup(key: string, contexts: EmailTemplateContext[]): unknown {
	// Self-reference, case-insensitively to match the `#each` keyword handling.
	// Without this, `{{This}}` fell through to the own-property scan and resolved
	// to `Object.prototype.toString`, rendering engine function source.
	if (key.toLowerCase() === 'this' || key === '.') return contexts[contexts.length - 1];
	for (let index = contexts.length - 1; index >= 0; index -= 1) {
		const context = contexts[index];
		// Own properties only: `in` also matched inherited members, so a template
		// could read `{{constructor}}`, `{{toString}}` or `{{__proto__}}` and emit
		// engine internals (or "[object Object]") instead of leaving an unknown
		// placeholder empty.
		if (context && typeof context === 'object' && Object.prototype.hasOwnProperty.call(context, key)) {
			return (context as Record<string, unknown>)[key];
		}
	}
	return undefined;
}

function truthy(value: unknown): boolean {
	if (Array.isArray(value)) return value.length > 0;
	return value !== undefined && value !== null && value !== false && value !== 0 && value !== '';
}

function renderNodes(nodes: Node[], contexts: EmailTemplateContext[], options: RenderOptions): string {
	return nodes.map((node) => {
		if (node.type === 'text') return node.value;
		if (node.type === 'if') {
			const value = lookup(node.key, contexts);
			return renderNodes(truthy(value) ? node.yes : node.no, contexts, options);
		}
		if (node.type === 'each') {
			const value = lookup(node.key, contexts);
			if (!Array.isArray(value)) return '';
			return value.map((item) => renderNodes(node.children, [...contexts, item as EmailTemplateContext], options)).join('');
		}
		const value = lookup(node.key, contexts);
		if (value === undefined) return options.preserveUnknown ? (node.raw ? `{{{${node.key}}}}` : `{{${node.key}}}`) : '';
		const text = value === null ? '' : String(value);
		return node.raw || options.rawHtmlKeys?.has(node.key) ? text : escapeHtml(text);
	}).join('');
}

/** Render the safe Handlebars subset used by advisory email templates. */
export function renderEmailTemplate(
	template: string,
	values: Record<string, unknown>,
	options: RenderOptions = {},
): string {
	return renderNodes(parse(template), [values], options);
}
