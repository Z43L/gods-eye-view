/**
 * Hermetic tests for the BGP prefix bulk importer: stubbed RIPEstat,
 * throwaway DB in os.tmpdir().
 */

import { strict as assert } from 'node:assert';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { test } from 'node:test';

import { openInventory } from '../../server/network/inventory.mjs';
import { importPrefixes } from '../../server/network/import-prefixes.mjs';

const PREFIXES_FIXTURE = {
  data: { prefixes: [{ prefix: '81.9.160.0/19' }, { prefix: '2001:db8::/32' }] },
};
const OVERVIEW_FIXTURE = { data: { holder: 'EUSKALTEL Euskaltel S.A.' } };

function stubFetch() {
  const original = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const body = String(url).includes('as-overview') ? OVERVIEW_FIXTURE : PREFIXES_FIXTURE;
    return { ok: true, status: 200, json: async () => body };
  };
  return () => {
    globalThis.fetch = original;
  };
}

test('importPrefixes upserts one network + one observation per prefix', async () => {
  const restore = stubFetch();
  const dir = mkdtempSync(join(tmpdir(), 'gev-import-test-'));
  const inv = openInventory(join(dir, 'test.db'));
  try {
    const first = await importPrefixes('as12338', { inventory: inv });
    assert.equal(first.asn, 'AS12338');
    assert.equal(first.total, 2);
    assert.equal(first.created, 2);
    assert.equal(first.updated, 0);

    const networks = inv.listNetworks({ limit: 10 });
    assert.equal(networks.length, 2);
    assert.ok(networks.every((n) => n.inputType === 'cidr'));

    const v4 = inv.getNetwork(networks.find((n) => n.normalizedQuery === '81.9.160.0/19').id);
    assert.equal(v4.observations.length, 1);
    assert.equal(v4.observations[0].source, 'ripestat');
    assert.equal(v4.observations[0].detail.kind, 'bgp-announced-prefix');

    // Idempotent re-run: same rows, refreshed last_seen, one more observation each.
    const second = await importPrefixes('AS12338', { inventory: inv });
    assert.equal(second.created, 0);
    assert.equal(second.updated, 2);
    assert.equal(inv.listNetworks({ limit: 10 }).length, 2);
    const v4b = inv.getNetwork(v4.id);
    assert.equal(v4b.observations.length, 2);
  } finally {
    restore();
    inv.close();
  }
});

test('importPrefixes rejects a non-ASN input', async () => {
  const restore = stubFetch();
  const dir = mkdtempSync(join(tmpdir(), 'gev-import-test-'));
  const inv = openInventory(join(dir, 'test.db'));
  try {
    await assert.rejects(() => importPrefixes('not-an-asn', { inventory: inv }), /Not an ASN/);
  } finally {
    restore();
    inv.close();
  }
});
