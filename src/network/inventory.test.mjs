import test from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import {
  openInventory,
  resolveDbPath,
  DEFAULT_DB_PATH,
} from '../../server/network/inventory.mjs';

function tempDbPath() {
  return join(mkdtempSync(join(tmpdir(), 'gev-inv-')), 'inv.db');
}

function sampleDossier(overrides = {}) {
  return {
    query: '1.2.3.4',
    normalizedQuery: '1.2.3.4',
    inputType: 'ip',
    title: 'IP 1.2.3.4 — test',
    summary: 'dossier de prueba',
    confidence: 'media',
    confidenceScore: 0.55,
    lat: 40.4168,
    lon: -3.7038,
    radiusM: 25000,
    facts: [{ label: 'Ciudad', value: 'Madrid', source: 'ip-api' }],
    evidence: [],
    candidates: [],
    sources: [{ name: 'ip-api', status: 'ok', note: null }],
    hosts: [{ value: '1.2.3.4', kind: 'ip' }],
    fetchedAt: new Date().toISOString(),
    ...overrides,
  };
}

test('resolveDbPath honors explicit path, env, then default', () => {
  assert.equal(resolveDbPath('/tmp/x.db'), '/tmp/x.db');
  const prev = process.env.GEV_INVENTORY_DB;
  process.env.GEV_INVENTORY_DB = '/tmp/env.db';
  try {
    assert.equal(resolveDbPath(), '/tmp/env.db');
  } finally {
    if (prev === undefined) delete process.env.GEV_INVENTORY_DB;
    else process.env.GEV_INVENTORY_DB = prev;
  }
  assert.ok(DEFAULT_DB_PATH.endsWith(join('data', 'network-inventory.db')));
  assert.equal(resolveDbPath(), DEFAULT_DB_PATH);
});

test('schema creates all inventory tables', () => {
  const inv = openInventory(tempDbPath());
  try {
    const tables = inv.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
      )
      .all()
      .map((r) => r.name);
    for (const t of ['networks', 'hosts', 'services', 'observations', 'sources']) {
      assert.ok(tables.includes(t), `missing table ${t}`);
    }
  } finally {
    inv.close();
  }
});

test('upsertNetwork is idempotent on (normalized_query, input_type)', () => {
  const inv = openInventory(tempDbPath());
  try {
    const first = inv.upsertNetwork(sampleDossier());
    assert.ok(Number.isInteger(first.id));
    assert.equal(first.created, true);
    const second = inv.upsertNetwork(
      sampleDossier({ title: 'IP 1.2.3.4 — updated', confidenceScore: 0.9 }),
    );
    assert.equal(second.id, first.id);
    assert.equal(second.created, false);
    const row = inv.getNetwork(first.id);
    assert.equal(row.title, 'IP 1.2.3.4 — updated');
    assert.equal(row.confidenceScore, 0.9);
    assert.deepEqual(row.facts, [{ label: 'Ciudad', value: 'Madrid', source: 'ip-api' }]);
    assert.deepEqual(row.sources, [{ name: 'ip-api', status: 'ok', note: null }]);
    assert.equal(row.normalizedQuery, '1.2.3.4');
    // Same normalized query but different input type = different row.
    const other = inv.upsertNetwork(
      sampleDossier({ inputType: 'hostname', normalizedQuery: '1.2.3.4' }),
    );
    assert.notEqual(other.id, first.id);
  } finally {
    inv.close();
  }
});

test('upsertNetwork stores hosts and refreshes source states', () => {
  const inv = openInventory(tempDbPath());
  try {
    const { id } = inv.upsertNetwork(
      sampleDossier({
        hosts: [
          { value: '1.2.3.4', kind: 'ip' },
          { value: 'host.example.com', kind: 'ptr' },
        ],
        sources: [
          { name: 'ip-api', status: 'ok' },
          { name: 'wigle', status: 'needs_token', note: 'WIGLE_API_NAME/WIGLE_API_TOKEN' },
        ],
      }),
    );
    const row = inv.getNetwork(id);
    assert.deepEqual(
      row.hosts.map((h) => h.value).sort(),
      ['1.2.3.4', 'host.example.com'],
    );
    const states = inv.db
      .prepare('SELECT name, status FROM sources ORDER BY name')
      .all()
      .map(({ name, status }) => ({ name, status }));
    assert.deepEqual(states, [
      { name: 'ip-api', status: 'ok' },
      { name: 'wigle', status: 'needs_token' },
    ]);
  } finally {
    inv.close();
  }
});

test('recordObservation appends one row per execution', () => {
  const inv = openInventory(tempDbPath());
  try {
    const { id } = inv.upsertNetwork(sampleDossier());
    inv.recordObservation(id, { source: 'triangulate', detail: { a: 1 } });
    inv.recordObservation(id, { source: 'triangulate', detail: { a: 2 } });
    const row = inv.getNetwork(id);
    assert.equal(row.observations.length, 2);
    assert.ok(row.observations.every((o) => o.source === 'triangulate'));
    assert.deepEqual(
      row.observations.map((o) => o.detail).sort((a, b) => a.a - b.a),
      [{ a: 1 }, { a: 2 }],
    );
  } finally {
    inv.close();
  }
});

test('listNetworks orders by last_seen desc and respects limit', async () => {
  const inv = openInventory(tempDbPath());
  try {
    inv.upsertNetwork(sampleDossier({ normalizedQuery: '1.1.1.1' }));
    await new Promise((r) => setTimeout(r, 15));
    inv.upsertNetwork(sampleDossier({ normalizedQuery: '2.2.2.2' }));
    const list = inv.listNetworks({ limit: 10 });
    assert.equal(list.length, 2);
    assert.equal(list[0].normalizedQuery, '2.2.2.2');
    assert.equal(list[1].normalizedQuery, '1.1.1.1');
    const limited = inv.listNetworks({ limit: 1 });
    assert.equal(limited.length, 1);
    assert.equal(limited[0].normalizedQuery, '2.2.2.2');
  } finally {
    inv.close();
  }
});

test('getNetwork returns null for unknown id', () => {
  const inv = openInventory(tempDbPath());
  try {
    assert.equal(inv.getNetwork(999999), null);
  } finally {
    inv.close();
  }
});

test('DatabaseSync is the stdlib module (no native deps)', () => {
  assert.equal(typeof DatabaseSync, 'function');
});
