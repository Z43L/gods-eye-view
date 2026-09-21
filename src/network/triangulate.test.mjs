import test from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import {
  normalizeQuery,
  fuseEvidence,
  triangulateNetwork,
  persistDossier,
  summarizeDossier,
  FETCH_TIMEOUT_MS,
} from '../../server/network/triangulate.mjs';
import { openInventory } from '../../server/network/inventory.mjs';

// --- normalizeQuery ----------------------------------------------------------

test('normalizeQuery classifies ip inputs', () => {
  assert.deepEqual(normalizeQuery('  1.2.3.4 '), {
    inputType: 'ip',
    normalizedQuery: '1.2.3.4',
  });
  assert.deepEqual(normalizeQuery('2001:DB8::1'), {
    inputType: 'ip',
    normalizedQuery: '2001:db8::1',
  });
});

test('normalizeQuery classifies hostnames', () => {
  assert.deepEqual(normalizeQuery('Example.COM.'), {
    inputType: 'hostname',
    normalizedQuery: 'example.com',
  });
  assert.deepEqual(normalizeQuery('router-mad1.isp.net'), {
    inputType: 'hostname',
    normalizedQuery: 'router-mad1.isp.net',
  });
});

test('normalizeQuery classifies bssid inputs', () => {
  assert.deepEqual(normalizeQuery('aa-bb-cc-dd-ee-ff'), {
    inputType: 'bssid',
    normalizedQuery: 'AA:BB:CC:DD:EE:FF',
  });
  assert.deepEqual(normalizeQuery('aabbccddeeff'), {
    inputType: 'bssid',
    normalizedQuery: 'AA:BB:CC:DD:EE:FF',
  });
  assert.deepEqual(normalizeQuery('AA:BB:CC:DD:EE:FF'), {
    inputType: 'bssid',
    normalizedQuery: 'AA:BB:CC:DD:EE:FF',
  });
});

test('normalizeQuery classifies ssid inputs', () => {
  assert.deepEqual(normalizeQuery('  Mi WiFi Casa  '), {
    inputType: 'ssid',
    normalizedQuery: 'Mi WiFi Casa',
  });
});

test('normalizeQuery classifies asn inputs', () => {
  for (const raw of ['12345', 'as12345', 'AS12345', ' As12345 ']) {
    assert.deepEqual(normalizeQuery(raw), {
      inputType: 'asn',
      normalizedQuery: 'AS12345',
    });
  }
});

test('normalizeQuery rejects empty input', () => {
  assert.throws(() => normalizeQuery('   '), /must not be empty/);
});

// --- fuseEvidence ------------------------------------------------------------

function ev(source, lat, lon, radiusM, weight) {
  return {
    source,
    lat,
    lon,
    radiusM,
    weight,
    observedAt: new Date().toISOString(),
    detail: null,
  };
}

test('fuseEvidence fuses agreeing sources into a weighted centroid', () => {
  const fused = fuseEvidence([
    ev('ip-api', 40.4168, -3.7038, 25000, 0.4),
    ev('ripestat-geoloc', 40.42, -3.7, 50000, 0.5),
  ]);
  assert.equal(fused.conflict, false);
  assert.ok(Math.abs(fused.lat - 40.418) < 0.01);
  assert.ok(Math.abs(fused.lon - -3.702) < 0.01);
  assert.ok(fused.radiusM > 0);
  assert.ok(fused.confidenceScore >= 0 && fused.confidenceScore <= 1);
});

test('fuseEvidence detects conflict between distant strong sources', () => {
  const fused = fuseEvidence([
    ev('wigle', 40.4168, -3.7038, 50, 1.0), // Madrid
    ev('beacondb', 51.5074, -0.1278, 100, 0.7), // London
  ]);
  assert.equal(fused.conflict, true);
  assert.equal(fused.confidence, 'baja');
  assert.equal(fused.candidates.length, 2);
  assert.ok(fused.notes.some((n) => /discrepan/.test(n)));
});

test('fuseEvidence handles zero evidence honestly', () => {
  const fused = fuseEvidence([]);
  assert.equal(fused.lat, null);
  assert.equal(fused.confidence, 'baja');
});

test('FETCH_TIMEOUT_MS is short (5s)', () => {
  assert.equal(FETCH_TIMEOUT_MS, 5000);
});

// --- triangulateNetwork (stubbed network) ------------------------------------

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(payload),
  };
}

/** Deterministic stub for every passive source used by the engine. */
function stubFetch(failures = {}) {
  return async (url, options = {}) => {
    const u = String(url);
    for (const key of Object.keys(failures)) {
      if (u.includes(key)) throw new Error(failures[key]);
    }
    if (u.includes('ip-api.com')) {
      return jsonResponse({
        status: 'success',
        query: '1.2.3.4',
        country: 'España',
        countryCode: 'ES',
        regionName: 'Madrid',
        city: 'Madrid',
        lat: 40.4168,
        lon: -3.7038,
        isp: 'Example ISP',
        org: 'Example Org',
        as: 'AS12345 Example',
        timezone: 'Europe/Madrid',
      });
    }
    if (u.includes('stat.ripe.net/data/geoloc')) {
      return jsonResponse({
        data: {
          locations: [
            { latitude: 40.42, longitude: -3.7, city: 'Madrid', country: 'ES', engine: 'ripe' },
          ],
        },
      });
    }
    if (u.includes('stat.ripe.net/data/prefix-overview')) {
      return jsonResponse({
        data: { asns: [{ asn: 12345, holder: 'Example' }], resource: '1.2.3.0/24' },
      });
    }
    if (u.includes('stat.ripe.net/data/as-overview')) {
      return jsonResponse({
        data: { holder: 'Example Holder', block: { resource: '1.2.3.0/24', name: 'EXAMPLE' } },
      });
    }
    if (u.includes('peeringdb.com/api/net?')) {
      return jsonResponse({ data: [{ id: 7, name: 'ExampleNet', website: 'https://example.net' }] });
    }
    if (u.includes('peeringdb.com/api/netfac')) {
      return jsonResponse({ data: [{ fac_id: 10 }] });
    }
    if (u.includes('peeringdb.com/api/fac/')) {
      return jsonResponse({
        data: [{ name: 'Example IX', city: 'Madrid', country: 'ES', latitude: '40.41', longitude: '-3.70' }],
      });
    }
    if (u.includes('crt.sh')) {
      return jsonResponse([{ name_value: 'example.com\nwww.example.com' }]);
    }
    if (u.includes('api.wigle.net')) {
      return jsonResponse({
        results: [{ trilat: 40.417, trilong: -3.704, ssid: 'TestSSID' }],
        totalResults: 3,
      });
    }
    if (u.includes('beacon.berylia.org')) {
      assert.equal(options.method, 'POST');
      return jsonResponse({ location: { lat: 40.418, lng: -3.705, accuracy: 50 } });
    }
    if (u.includes('opencellid.org')) {
      return jsonResponse([{ lat: 40.419, lon: -3.706, radio: 'LTE', mcc: '214', mnc: '01' }]);
    }
    return jsonResponse({ error: 'stub: unknown url ' + u }, 404);
  };
}

const stubDns = {
  lookup: async (host) => ({ address: '1.2.3.4', family: 4 }),
  reverse: async (ip) => ['4-3-2-1.mad1.example.net.'],
};

function tempDbPath() {
  return join(mkdtempSync(join(tmpdir(), 'gev-tri-')), 'inv.db');
}

test('triangulateNetwork builds a full dossier for an IP (stubbed)', async () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = await triangulateNetwork('1.2.3.4', {
      fetch: stubFetch(),
      dns: stubDns,
      env: { OPENCELLID_TOKEN: 'tok' },
      inventory: inv,
      persist: true,
    });
    assert.equal(dossier.normalizedQuery, '1.2.3.4');
    assert.equal(dossier.inputType, 'ip');
    assert.ok(['baja', 'media', 'alta'].includes(dossier.confidence));
    assert.ok(dossier.confidenceScore >= 0 && dossier.confidenceScore <= 1);
    assert.ok(Number.isFinite(dossier.lat) && Number.isFinite(dossier.lon));
    assert.ok(dossier.radiusM > 0);
    assert.ok(Array.isArray(dossier.facts) && dossier.facts.length > 0);
    assert.ok(Array.isArray(dossier.evidence) && dossier.evidence.length >= 3);
    for (const e of dossier.evidence) {
      assert.ok(e.source && Number.isFinite(e.lat) && Number.isFinite(e.radiusM));
      assert.ok(e.weight > 0 && e.weight <= 1);
    }
    const statuses = Object.fromEntries(dossier.sources.map((s) => [s.name, s.status]));
    assert.equal(statuses['ip-api'], 'ok');
    assert.equal(statuses['ripestat-geoloc'], 'ok');
    assert.equal(statuses.rdns, 'ok');
    assert.equal(statuses['crt.sh'], 'ok');
    assert.equal(statuses.opencellid, 'ok');
    // rDNS city-code parsing: mad1 -> Madrid evidence
    assert.ok(
      dossier.evidence.some((e) => e.source === 'rdns'),
      'expected rdns evidence from mad1 city code',
    );
    assert.ok(
      dossier.facts.some((f) => f.label === 'Ciudad inferida (rDNS)' && f.value === 'Madrid'),
    );
    // Persisted: one network row + one observation row.
    const rows = inv.listNetworks({ limit: 10 });
    assert.equal(rows.length, 1);
    assert.equal(rows[0].normalizedQuery, '1.2.3.4');
    const full = inv.getNetwork(rows[0].id);
    assert.equal(full.observations.length, 1);
    assert.equal(full.observations[0].source, 'triangulate');
  } finally {
    inv.close();
  }
});

test('a failing source becomes unavailable, never an exception', async () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = await triangulateNetwork('1.2.3.4', {
      fetch: stubFetch({ 'stat.ripe.net': 'boom', 'crt.sh': 'boom' }),
      dns: stubDns,
      env: {},
      inventory: inv,
    });
    const statuses = Object.fromEntries(dossier.sources.map((s) => [s.name, s.status]));
    assert.equal(statuses['ripestat-geoloc'], 'unavailable');
    assert.equal(statuses['crt.sh'], 'unavailable');
    assert.equal(statuses['ip-api'], 'ok');
    assert.ok(dossier.summary.length > 0);
  } finally {
    inv.close();
  }
});

test('token-gated sources report needs_token without credentials', async () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = await triangulateNetwork('AA:BB:CC:DD:EE:FF', {
      fetch: stubFetch(),
      dns: stubDns,
      env: {},
      inventory: inv,
    });
    const statuses = Object.fromEntries(dossier.sources.map((s) => [s.name, s.status]));
    assert.equal(statuses.wigle, 'needs_token');
    assert.equal(statuses.opencellid, 'needs_token');
    assert.equal(statuses.beacondb, 'ok');
    assert.equal(dossier.inputType, 'bssid');
  } finally {
    inv.close();
  }
});

test('anycast IPs get an honest confidence ceiling', async () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = await triangulateNetwork('8.8.8.8', {
      fetch: stubFetch(),
      dns: stubDns,
      env: {},
      inventory: inv,
    });
    assert.ok(dossier.confidenceScore <= 0.25);
    assert.equal(dossier.confidence, 'baja');
    assert.ok(/anycast/i.test(dossier.summary));
  } finally {
    inv.close();
  }
});

test('hostname input resolves via DNS first', async () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = await triangulateNetwork('example.com', {
      fetch: stubFetch(),
      dns: stubDns,
      env: {},
      inventory: inv,
    });
    assert.equal(dossier.inputType, 'hostname');
    assert.ok(dossier.facts.some((f) => f.label === 'Resolución DNS'));
    assert.ok(dossier.hosts.some((h) => h.value === '1.2.3.4' && h.kind === 'ip'));
  } finally {
    inv.close();
  }
});

test('persistDossier upserts and records one observation per call', () => {
  const inv = openInventory(tempDbPath());
  try {
    const dossier = {
      query: '9.9.9.9',
      normalizedQuery: '9.9.9.9',
      inputType: 'ip',
      title: 't',
      summary: 's',
      confidence: 'baja',
      confidenceScore: 0.2,
      lat: null,
      lon: null,
      radiusM: null,
      facts: [],
      evidence: [],
      candidates: [],
      sources: [{ name: 'ip-api', status: 'empty' }],
      fetchedAt: new Date().toISOString(),
    };
    const id1 = persistDossier(dossier, inv);
    const id2 = persistDossier({ ...dossier, confidenceScore: 0.3 }, inv);
    assert.equal(id1, id2);
    const full = inv.getNetwork(id1);
    assert.equal(full.confidenceScore, 0.3);
    assert.equal(full.observations.length, 2);
  } finally {
    inv.close();
  }
});

test('summarizeDossier caps evidence/facts for agent responses', () => {
  const dossier = {
    query: 'x',
    normalizedQuery: 'x',
    inputType: 'ssid',
    title: 't',
    summary: 's',
    confidence: 'media',
    confidenceScore: 0.5,
    lat: 1,
    lon: 2,
    radiusM: 100,
    conflict: false,
    facts: Array.from({ length: 30 }, (_, i) => ({ label: `f${i}`, value: 'v', source: 's' })),
    evidence: Array.from({ length: 30 }, (_, i) => ({ source: 's', lat: 1, lon: 2, radiusM: 1, weight: 0.5 })),
    candidates: [],
    sources: [],
    fetchedAt: 't',
  };
  const summary = summarizeDossier(dossier);
  assert.equal(summary.facts.length, 25);
  assert.equal(summary.evidence.length, 10);
  assert.equal(summary.normalizedQuery, 'x');
});
