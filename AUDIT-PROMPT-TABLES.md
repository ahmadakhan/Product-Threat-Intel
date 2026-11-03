# Comprehensive Code Audit Prompt

## Context
You are auditing the VulnStream-Enterprise codebase, a vulnerability intelligence platform that aggregates CVE feeds, correlates them with CPE assets, generates advisories, and delivers notifications via email/webhooks.

## Recent Changes
The codebase has recently undergone a significant styling consolidation (commit 6f70f4e):
- All per-component table CSS duplicates were removed from audit-trail.css, correlation.css, ml-logs.css, and threat-search.css
- The `divide-y` Tailwind classes were removed from all table `<tbody>` elements across 15+ components
- Canonical data table styling is now centralized in `src/index.css` under `.ui-main table` rules
- The audit-trail.css no longer has `:is(th, td)` padding, `td` border-bottom, `tr:last-child td` border removal, or `tbody tr:hover` background rules
- Feeds tables use a scoped override `.ui-main .feeds-table :is(th, td)` for tighter horizontal padding

## Audit Scope

### 1. Table Styling Consistency (HIGHEST PRIORITY)
Every `<table>` element inside `.ui-main` should inherit the canonical styling from `src/index.css`:
- `width: 100%`, `border-collapse: separate`, `border-spacing: 0`
- `thead` with subtle background
- `th` with 13px 24px padding, muted color, 10px font-size, 650 weight, 0.06em letter-spacing, uppercase, bottom border
- `td` with 22px 24px padding, top vertical-align, divider bottom border
- `tbody tr:last-child td` with no bottom border
- `tbody tr:hover` with control-hover background
- `td[colspan]` with 48px block padding

**Check each component:**
1. Verify no `divide-y` classes remain on `<tbody>` elements
2. Verify no per-component CSS still overrides `.ui-main table` rules (padding, borders, hover)
3. Verify tables without `.ui-main` parent still get appropriate styling
4. Verify `.feeds-table` scoped override still works correctly
5. Check that `audit-actions-table` and `ml-logs-table` classes still function after CSS removal
6. Verify `correlation.css` removed rules don't break `.cr-match-table`
7. Verify `threat-search.css` removed rules don't break `.threat-results-table`

### 2. CSS Cascade Issues
- Check if `.ui-main table` rules properly override component-specific table styles
- Verify no specificity conflicts between `.ui-main table` and component classes
- Check that `!important` isn't needed anywhere
- Verify dark/light theme compatibility for all table styles

### 3. Component-Level Table Issues
For each of these components, verify table styling is correct:
- `AlertedCVEsView.tsx` - removed `divide-y` from tbody
- `EmailHistoryView.tsx` - removed `divide-y` from tbody
- `EmailQueueView.tsx` - removed `divide-y` from tbody
- `FindingsView.tsx` - removed `divide-y` from tbody
- `RecipientsView.tsx` - removed `divide-y` from two tbodys
- `ThreatDataView.tsx` - removed `divide-y` from tbody
- `ThreatFeedsView.tsx` - removed `divide-y` from tbody
- `ThreatIntelligenceSearch.tsx` - removed `divide-y` from tbody
- `WatchListView.tsx` - removed `divide-y` from tbody
- `OperationalLogsView.tsx` - uses `audit-actions-table` class
- `MlLogsView.tsx` - uses `ml-logs-table` class
- `CorrelationDashboard.tsx` - uses `cr-match-table` class
- `ThreatIntelligenceSearch.tsx` - uses `threat-results-table` class
- `ThreatFeedsView.tsx` - uses `feeds-table` class

### 4. OperationalLogsView Specific
- Verify the audit trail tab table and operational events table have identical styling
- Check that `audit-entries-panel`, `audit-entries-heading`, `audit-desktop-table`, `audit-actions-table` classes are properly applied
- Verify header text alignment matches between both tables
- Verify row hover cursor pointer is consistent
- Check `border-bottom` on `td` elements uses `--ui-divider` variable

### 5. Index.css Table Rules Verification
Verify the following rules in `src/index.css`:
```
.ui-main table { width: 100%; border-collapse: separate; border-spacing: 0; }
.ui-main table thead { background: var(--ui-subtle); }
.ui-main table th { padding: 13px 24px; color: var(--ui-muted); font-size: 10px; font-weight: 650; letter-spacing: 0.06em; text-transform: uppercase; border-bottom: 1px solid var(--ui-divider); }
.ui-main table td { padding: 22px 24px; vertical-align: top; border-color: var(--ui-divider); border-bottom: 1px solid var(--ui-divider); }
.ui-main table tbody tr:last-child td { border-bottom: 0; }
.ui-main table tbody tr { transition: background-color 140ms ease; }
.ui-main table tbody tr:hover { background-color: var(--ui-control-hover); }
.ui-main table td[colspan] { padding-block: 48px; }
```

### 6. Build and Test Verification
- Run `npm run lint` (tsc --noEmit) - must pass with 0 errors
- Run `npm test` (node --import tsx --test) - all tests must pass
- Run `npm run test:unit` (vitest run) - all tests must pass
- Verify production build succeeds
- Check for any TypeScript errors in modified files

### 7. Visual Regression Checks
- Verify table headers are properly aligned
- Verify row borders display correctly (single divider between rows, no border on last row)
- Verify hover state works on all table rows
- Verify colspan cells have proper padding
- Verify responsive behavior on smaller screens
- Check dark/light theme compatibility

### 8. Edge Cases
- Tables inside modals (LogDetailModal, EventDetailPanel)
- Tables inside dialogs (SettingsView dialogs)
- Nested tables (if any)
- Tables with very few rows (1-2 rows) - border-bottom removal should work
- Tables with colspan cells spanning all columns
- Empty tables (no data) - should show empty state properly

## Output Format
For each finding, provide:
- **File**: path and line number
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Category**: Security / Performance / Reliability / Maintainability / Testing / Styling
- **Description**: what the issue is
- **Impact**: what could happen if not fixed
- **Fix**: specific code change recommended
- **Effort**: S / M / L / XL

## Priority Order
1. Broken table styling (missing borders, hover, padding)
2. CSS specificity conflicts
3. Inconsistent styling across components
4. Visual regression issues
5. Performance issues from CSS changes
6. Code quality improvements

## Exclusions
- Do not report issues in `node_modules/`, `dist/`, `server-dist/`
- Do not report style/formatting issues (handled by linter)
- Skip generated files (migrations with auto-generated content)
- Do not modify any code - only report findings