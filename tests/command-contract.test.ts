import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { CommandResult as ClientCommandResult } from '../src/types/index.ts';
import type { CommandResult as ServerCommandResult } from '../server/commands.ts';

/**
 * The browser reads `POST /api/commands` through a locally declared
 * `CommandResult` (the bundle must not import server modules). This keeps the two
 * definitions from drifting: every field the client names must exist on the
 * server's type with an assignable type.
 */
test('the client CommandResult matches the server contract', () => {
  // Compile-time check: a server response must satisfy the client type.
  const serverShaped: ServerCommandResult = { success: true, imported: 2, errors: [] };
  const asClient: ClientCommandResult = serverShaped;
  assert.equal(asClient.success, true);

  // Runtime check: every optional field the client declares exists in the server
  // source, so a rename on one side fails here instead of at runtime.
  const serverSource = readFileSync(new URL('../server/commands.ts', import.meta.url), 'utf8');
  const block = /export interface CommandResult \{([\s\S]*?)\n\}/.exec(serverSource)?.[1] ?? '';
  assert.ok(block, 'server CommandResult interface must exist');
  for (const field of ['success', 'imported', 'errors', 'assetId', 'recipientId', 'webhookId', 'cveId', 'action'])
    assert.match(block, new RegExp(`\\b${field}\\??:`), `server CommandResult must declare ${field}`);
});
