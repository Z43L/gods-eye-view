import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { NETWORK_DESCRIPTIONS } from '../descriptions.js';

const here = dirname(fileURLToPath(import.meta.url));
const serverPath = join(here, '..', 'server.mjs');

test('network tools have agent-facing descriptions', () => {
  for (const name of ['network_triangulate', 'network_inventory_list']) {
    const description = NETWORK_DESCRIPTIONS[name];
    assert.ok(
      typeof description === 'string' && description.length > 40,
      `missing/short description for ${name}`,
    );
  }
});

/** Spawn the real MCP server over stdio and check the tools surface. */
async function listServerTools() {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    env: { ...process.env, GEV_INVENTORY_DB: ':memory:' },
  });
  const client = new Client({ name: 'network-tools-test', version: '0.0.0' });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    return tools;
  } finally {
    await client.close();
  }
}

test(
  'server registers network_triangulate and network_inventory_list',
  { timeout: 30000 },
  async () => {
    const tools = await listServerTools();
    const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
    assert.ok(byName.network_triangulate, 'network_triangulate missing');
    assert.ok(byName.network_inventory_list, 'network_inventory_list missing');

    const triangulateSchema =
      byName.network_triangulate.inputSchema?.properties ?? {};
    assert.ok(triangulateSchema.query, 'network_triangulate needs a query arg');

    const listSchema = byName.network_inventory_list.inputSchema?.properties ?? {};
    assert.ok('limit' in listSchema, 'network_inventory_list needs a limit arg');
    assert.ok(
      byName.network_triangulate.description.length > 40 &&
        byName.network_inventory_list.description.length > 40,
    );
  },
);
