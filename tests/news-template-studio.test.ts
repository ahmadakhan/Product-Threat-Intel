import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
  DEFAULT_NEWS_EMAIL_TEMPLATE,
  compileNewsTemplate,
  renderNewsTemplate,
  type NewsTemplateParts,
} from '../src/utils/templateCompiler.ts';

/**
 * The News Template Studio showed "Template HTML Source" and "Live Rendered
 * Preview" as two different documents. They were: the compiler ignored the
 * customization entirely, the preview rendered with a hard-coded digest
 * customization, and the app state fell back to the stock string. These tests
 * pin the three contracts that keep the studio self-consistent.
 */

const parts: NewsTemplateParts = {
  news_title: 'Security News',
  news_subject_badge_text: 'THREAT BRIEFING',
  news_subject: '[Threat intelligence] [NEWS] 1 article: Example',
  news_date: '22 Nov 2026',
  news_count: 1,
  news_summary: 'One article matched your inventory.',
  news_sources: [
    {
      title: 'Example story',
      url: 'https://example.com/story',
      source_name: 'Example Feed',
      published_at: '22 Nov 2026',
      excerpt: 'Example excerpt.',
    },
  ],
  news_articles: '',
  sources_hub_url: 'https://example.com/hub',
  news_footer: 'Sample footer.',
};

test('the news defaults compile to the shipped document byte for byte', () => {
  // An operator who never opened the styling tools must get exactly the layout
  // that ships, otherwise every existing installation silently changes.
  assert.equal(compileNewsTemplate(DEFAULT_NEWS_EMAIL_CUSTOMIZATION), DEFAULT_NEWS_EMAIL_TEMPLATE);
});

test('the news compiler applies the studio customization', () => {
  const html = compileNewsTemplate({
    ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION,
    accentColor: '#7c3aed',
    canvasBg: '#fdf4ff',
    cardBg: '#fffaf0',
    headingColor: '#4c1d95',
    fontColor: '#3b0764',
    headerBg: '#faf5ff',
  });
  assert.match(html, /#7c3aed/, 'the accent colour reaches the markup');
  assert.ok(!html.includes('#1d4ed8'), 'no stock accent survives');
  assert.match(html, /#fdf4ff/, 'the canvas colour reaches the markup');
  assert.match(html, /#fffaf0/, 'the card colour reaches the markup');
  assert.match(html, /color: #4c1d95/, 'the heading colour reaches the markup');
  // The document is still a renderable template.
  assert.match(html, /\{\{news_title\}\}/);
  assert.match(html, /\{\{#each news_sources\}\}/);
});

test('the rendered news document follows the live customization', () => {
  const stock = renderNewsTemplate(DEFAULT_NEWS_EMAIL_CUSTOMIZATION, parts);
  const custom = renderNewsTemplate(
    { ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION, accentColor: '#7c3aed', canvasBg: '#fdf4ff' },
    parts,
  );
  assert.match(stock, /#1d4ed8/);
  assert.match(custom, /#7c3aed/);
  assert.match(custom, /#fdf4ff/, 'the preview applies the canvas colour, not a hard-coded default');
  assert.ok(!custom.includes('#1d4ed8'), 'the stock accent is gone once customized');
  // Both are fully rendered, and the source template still carries its tokens:
  // that difference is expected and is what the two inspector tabs describe.
  assert.ok(!stock.includes('{{'));
  assert.ok(!custom.includes('{{'));
  assert.match(DEFAULT_NEWS_EMAIL_TEMPLATE, /\{\{news_title\}\}/);
});

test('a saved custom template is rendered as-is, without recompiling it', () => {
  const custom = '<html><body><h1>{{news_title}}</h1><p>{{news_count}}</p></body></html>';
  const html = renderNewsTemplate({ ...DEFAULT_NEWS_EMAIL_CUSTOMIZATION, accentColor: '#7c3aed' }, parts, custom);
  assert.equal(html, '<html><body><h1>Security News</h1><p>1</p></body></html>');
});
