import test from 'node:test';
import assert from 'node:assert/strict';
import { unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import http from 'node:http';
import { ReconDatabase } from './db.mjs';
import { fingerprintTarget } from './fingerprint.mjs';
import { runTraceroute } from './traceroute.mjs';
import { runDnsRecon } from './dnsRecon.mjs';

const TEST_DB_PATH = join(process.cwd(), '.gev-cache', 'test-recon.db');

function cleanupDb() {
  if (existsSync(TEST_DB_PATH)) {
    try {
      unlinkSync(TEST_DB_PATH);
    } catch {}
  }
}

test('ReconDatabase (SQLite persistence CRUD operations)', () => {
  cleanupDb();
  const db = new ReconDatabase(TEST_DB_PATH);

  // 1. Upsert target
  const target = db.upsertTarget({
    id: 'cctv:austin:101',
    targetType: 'cctv',
    host: 'cctv.austintexas.gov',
    ip: '198.51.100.10',
    latitude: 30.2672,
    longitude: -97.7431,
    tags: ['cctv', 'austin', 'traffic'],
  });

  assert.equal(target.id, 'cctv:austin:101');
  assert.equal(target.host, 'cctv.austintexas.gov');
  assert.deepEqual(target.tags, ['cctv', 'austin', 'traffic']);

  // 2. Save HTTP Fingerprint
  db.saveFingerprint({
    targetId: 'cctv:austin:101',
    port: 443,
    protocol: 'https',
    statusCode: 200,
    serverBanner: 'nginx/1.24.0',
    pageTitle: 'Austin CCTV Stream Portal',
    securityHeaders: { hsts: 'max-age=31536000', csp: null },
    tlsSubject: 'cctv.austintexas.gov',
    tlsSans: ['cctv.austintexas.gov', 'stream.austintexas.gov'],
  });

  const fps = db.getFingerprints('cctv:austin:101');
  assert.equal(fps.length, 1);
  assert.equal(fps[0].port, 443);
  assert.equal(fps[0].server_banner, 'nginx/1.24.0');
  assert.deepEqual(fps[0].tls_sans, ['cctv.austintexas.gov', 'stream.austintexas.gov']);

  // 3. Save Network Trace
  db.saveNetworkTrace({
    targetId: 'cctv:austin:101',
    destinationIp: '198.51.100.10',
    totalHops: 3,
    totalRttMs: 24.5,
    hops: [
      { hop: 1, ip: '192.168.1.1', rttMs: 1.2 },
      { hop: 2, ip: '10.0.0.1', rttMs: 5.4 },
      { hop: 3, ip: '198.51.100.10', rttMs: 24.5, lat: 30.2672, lon: -97.7431 },
    ],
  });

  const traces = db.getNetworkTraces('cctv:austin:101');
  assert.equal(traces.length, 1);
  assert.equal(traces[0].total_hops, 3);
  assert.equal(traces[0].hops[2].ip, '198.51.100.10');

  // 4. Save DNS Records
  db.saveDnsRecords('cctv:austin:101', 'cctv.austintexas.gov', [
    { type: 'A', value: '198.51.100.10', ttl: 300 },
    { type: 'TXT', value: 'v=spf1 include:_spf.google.com ~all' },
  ]);

  const dnsRecs = db.getDnsRecords('cctv:austin:101');
  assert.equal(dnsRecs.length, 2);
  assert.equal(dnsRecs.find((r) => r.record_type === 'A').record_value, '198.51.100.10');

  // 5. Full dossier retrieval
  const dossier = db.getFullDossier('cctv:austin:101');
  assert.ok(dossier);
  assert.equal(dossier.target.id, 'cctv:austin:101');
  assert.equal(dossier.fingerprints.length, 1);
  assert.equal(dossier.network_traces.length, 1);
  assert.equal(dossier.dns_records.length, 2);

  // 6. List targets
  const targetList = db.listTargets({ limit: 10, tag: 'austin' });
  assert.equal(targetList.length, 1);
  assert.equal(targetList[0].id, 'cctv:austin:101');

  db.close();
  cleanupDb();
});

test('HTTP/TLS Fingerprinting Module', async () => {
  cleanupDb();
  const db = new ReconDatabase(TEST_DB_PATH);

  const mockProbeHttp = async (host, port, isHttps) => ({
    ok: true,
    port,
    protocol: isHttps ? 'https' : 'http',
    statusCode: 200,
    serverBanner: 'MockReconServer/2.0',
    pageTitle: 'Mock IoT Camera',
    authHeader: null,
    securityHeaders: { hsts: 'max-age=63072000', csp: null, x_frame_options: 'DENY', x_content_type_options: null, cors: null },
    rawHeaders: { server: 'MockReconServer/2.0' },
  });

  const mockProbeTls = async (host, port) => ({
    ok: true,
    subject: 'cam.mock.local',
    issuer: 'Mock CA',
    sans: ['cam.mock.local', 'stream.mock.local'],
    validFrom: Date.now() - 100000,
    validTo: Date.now() + 10000000,
  });

  const result = await fingerprintTarget({
    host: 'cam.mock.local',
    targetId: 'mock:cam:1',
    targetType: 'cctv',
    ports: [443],
    db,
    probeHttpFn: mockProbeHttp,
    probeTlsFn: mockProbeTls,
  });

  assert.equal(result.targetId, 'mock:cam:1');
  assert.equal(result.fingerprints.length, 1);
  const fp = result.fingerprints[0];
  assert.equal(fp.port, 443);
  assert.equal(fp.serverBanner, 'MockReconServer/2.0');
  assert.equal(fp.pageTitle, 'Mock IoT Camera');
  assert.equal(fp.securityHeaders.hsts, 'max-age=63072000');
  assert.equal(fp.tls.subject, 'cam.mock.local');

  // Verify stored in SQLite
  const stored = db.getFingerprints('mock:cam:1');
  assert.equal(stored.length, 1);
  assert.equal(stored[0].server_banner, 'MockReconServer/2.0');
  assert.deepEqual(stored[0].tls_sans, ['cam.mock.local', 'stream.mock.local']);

  db.close();
  cleanupDb();
});

test('DNS Reconnaissance Module', async () => {
  cleanupDb();
  const db = new ReconDatabase(TEST_DB_PATH);

  // Query a well-known public domain (or localhost fallback)
  const res = await runDnsRecon({
    domain: '127.0.0.1',
    targetId: 'target:localhost',
    db,
  });

  assert.equal(res.targetId, 'target:localhost');
  assert.ok(Array.isArray(res.records));

  // Verify stored in SQLite
  const stored = db.getDnsRecords('target:localhost');
  assert.ok(Array.isArray(stored));

  db.close();
  cleanupDb();
});

test('Traceroute Module with Geo/RTT resolution', async () => {
  cleanupDb();
  const db = new ReconDatabase(TEST_DB_PATH);

  const res = await runTraceroute({
    target: '127.0.0.1',
    targetId: 'trace:localhost',
    maxHops: 5,
    db,
  });

  assert.equal(res.targetId, 'trace:localhost');
  assert.ok(res.hops.length >= 1);
  assert.equal(res.hops[0].ip, '127.0.0.1');

  // Verify stored in SQLite
  const traces = db.getNetworkTraces('trace:localhost');
  assert.equal(traces.length, 1);
  assert.equal(traces[0].destination_ip, '127.0.0.1');

  db.close();
  cleanupDb();
});
