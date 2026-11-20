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
	const tokenPattern = /\{\{\{?\s*(#if\s+[^}\s]+|#each\s+[^}\s]+|\/[a-z]+|else|[^}]+?)\s*\}?\}\}/g;
	const tokens: Array<{ index: number; end: number; value: string; raw: boolean }> = [];
	for (let match = tokenPattern.exec(template); match; match = tokenPattern.exec(template)) {
		tokens.push({
			index: match.index,
			end: tokenPattern.lastIndex,
			value: match[0].startsWith('{{{') ? match[0].slice(3, -3).trim() : match[0].slice(2, -2).trim(),
			raw: match[0].startsWith('{{{'),
		});
	}
	let tokenIndex = 0;

	const sequence = (stops: Stop[] = []): { nodes: Node[]; stop?: Stop } => {
		const nodes: Node[] = [];
		let cursor = tokenIndex ? tokens[tokenIndex - 1].end : 0;
		while (tokenIndex < tokens.length) {
			const token = tokens[tokenIndex++];
			if (token.index > cursor) nodes.push({ type: 'text', value: template.slice(cursor, token.index) });
			cursor = token.end;
			if (stops.includes(token.value as Stop)) return { nodes, stop: token.value as Stop };
			const ifMatch = /^#if\s+([a-z_][a-z0-9_]*)$/i.exec(token.value);
			if (ifMatch) {
				const yes = sequence(['else', '/if']);
				if (!yes.stop) throw new Error('Unclosed {{#if}} block');
				const noResult = yes.stop === 'else' ? sequence(['/if']) : null;
				if (noResult && !noResult.stop) throw new Error('Unclosed {{#if}} block');
				const no = noResult?.nodes ?? [];
				nodes.push({ type: 'if', key: ifMatch[1], yes: yes.nodes, no });
				cursor = tokens[tokenIndex - 1]?.end ?? cursor;
				continue;
			}
			const eachMatch = /^#each\s+([a-z_][a-z0-9_]*)$/i.exec(token.value);
			if (eachMatch) {
				const result = sequence(['/each']);
				if (!result.stop) throw new Error('Unclosed {{#each}} block');
				const children = result.nodes;
				nodes.push({ type: 'each', key: eachMatch[1], children });
				cursor = tokens[tokenIndex - 1]?.end ?? cursor;
				continue;
			}
			if (token.value.startsWith('#') || token.value.startsWith('/')) continue;
			nodes.push({ type: 'value', key: token.value, raw: token.raw });
		}
		if (cursor < template.length) nodes.push({ type: 'text', value: template.slice(cursor) });
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
