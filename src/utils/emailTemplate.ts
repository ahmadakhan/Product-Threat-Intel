export type EmailTemplateContext = Record<string, unknown> | string | number | boolean | null;

type Node =
	| { type: 'text'; value: string }
	| { type: 'value'; key: string; raw: boolean }
	| { type: 'if'; key: string; yes: Node[]; no: Node[] }
	| { type: 'each'; key: string; children: Node[] };

type Stop = 'else' | '/if' | '/each';

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
	const tokenPattern = /\{\{\{?\s*(#if\s+[^}\s]+|#each\s+[^}\s]+|\/[a-z]+|[^}]+?)\s*\}?\}\}/g;
	let cursor = tokenPattern.lastIndex;

	const sequence = (stops: Stop[] = []): { nodes: Node[]; stop?: Stop } => {
		const nodes: Node[] = [];
		let match: RegExpExecArray | null;
		let cursor = tokenPattern.lastIndex;
		while ((match = tokenPattern.exec(template))) {
			if (match.index <= cursor) {
				// exec didn't advance past our position (lastIndex was reset to 0
				// by a prior null exec in a nested call). Stop to avoid an
				// infinite loop re-processing the same tokens.
				break;
			}
			if (match.index > cursor) nodes.push({ type: 'text', value: template.slice(cursor, match.index) });
			cursor = tokenPattern.lastIndex;
			const token = match[0];
			const inner = token.startsWith('{{{') ? token.slice(3, -3).trim() : token.slice(2, -2).trim();
			if (stops.includes(inner as Stop)) return { nodes, stop: inner as Stop };
			const ifMatch = /^#if\s+([a-z_][a-z0-9_]*)$/i.exec(inner);
			if (ifMatch) {
				const yes = sequence(['else', '/if']);
				cursor = tokenPattern.lastIndex;
				let no: Node[] = [];
				if (yes.stop === 'else') {
					no = sequence(['/if']).nodes;
					cursor = tokenPattern.lastIndex;
				}
				nodes.push({ type: 'if', key: ifMatch[1], yes: yes.nodes, no });
				continue;
			}
			const eachMatch = /^#each\s+([a-z_][a-z0-9_]*)$/i.exec(inner);
			if (eachMatch) {
				const children = sequence(['/each']).nodes;
				cursor = tokenPattern.lastIndex;
				nodes.push({ type: 'each', key: eachMatch[1], children });
				continue;
			}
			if (inner.startsWith('#') || inner.startsWith('/')) continue;
			nodes.push({ type: 'value', key: inner, raw: token.startsWith('{{{') });
		}
		if (cursor < template.length) nodes.push({ type: 'text', value: template.slice(cursor) });
		cursor = template.length;
		return { nodes };
	};

	return sequence().nodes;
}

function lookup(key: string, contexts: EmailTemplateContext[]): unknown {
	if (key === 'this' || key === '.') return contexts[contexts.length - 1];
	for (let index = contexts.length - 1; index >= 0; index -= 1) {
		const context = contexts[index];
		if (context && typeof context === 'object' && key in context) {
			return (context as Record<string, unknown>)[key];
		}
	}
	return undefined;
}

function truthy(value: unknown): boolean {
	if (Array.isArray(value)) return value.length > 0;
	return value !== undefined && value !== null && value !== false && value !== 0 && value !== '';
}

function renderNodes(
	nodes: Node[],
	contexts: EmailTemplateContext[],
	options: { preserveUnknown?: boolean; rawHtmlKeys?: ReadonlySet<string> },
): string {
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
	options: { preserveUnknown?: boolean; rawHtmlKeys?: ReadonlySet<string> } = {},
): string {
	return renderNodes(parse(template), [values], options);
}
