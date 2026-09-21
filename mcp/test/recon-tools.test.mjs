import test from 'node:test';
import assert from 'node:assert/strict';
import { RECON_DESCRIPTIONS } from '../descriptions.js';

test('active reconnaissance tools have detailed agent-facing descriptions', () => {
  const expectedTools = [
    'recon_fingerprint',
    'recon_traceroute',
    'recon_dns_lookup',
    'recon_inventory_query',
  ];

  for (const toolName of expectedTools) {
    const description = RECON_DESCRIPTIONS[toolName];
    assert.ok(
      typeof description === 'string' && description.length > 30,
      `missing or too short description for ${toolName}`,
    );
  }
});
