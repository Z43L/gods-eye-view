/**
 * Network inventory persistence — SQLite store for the passive network
 * triangulation engine.
 *
 * Everything here is passive data: dossiers produced by
 * `server/network/triangulate.mjs` from free public sources (ip-api,
 * RIPEstat, PeeringDB, crt.sh, reverse DNS, WiGLE, OpenCelliD, BeaconDB).
 * No active scanning of third-party networks happens anywhere in this
 * module — it only stores what the triangulation engine already observed.
 *
 * Tables:
 *   networks     one row per normalized query (upsert by
 *                normalized_query + input_type), with the latest fused
 *                dossier (position, confidence, facts, evidence,
 *                candidates, source states) and first/last seen stamps.
 *   hosts        hosts seen for a network (resolved IPs, PTR names, cert
 *                hostnames); populated opportunistically from dossiers.
 *   services     services fingerprinted on a host; reserved for the
 *                own-LAN discovery phase (schema only for now).
 *   observations one row per triangulation execution, with timestamp,
 *                source states and a detail payload.
 *   sources      last-known state per upstream source.
 *
 * The database file itself is runtime state and must never be committed
 * (see .gitignore). Override its location with GEV_INVENTORY_DB.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, '..', '..');

export const DEFAULT_DB_PATH = join(REPO_ROOT, 'data', 'network-inventory.db');

/** Resolve where the inventory database lives. */
export function resolveDbPath(dbPath) {
  if (dbPath) return dbPath;
  if (process.env.GEV_INVENTORY_DB) return process.env.GEV_INVENTORY_DB;
  return DEFAULT_DB_PATH;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS networks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  normalized_query TEXT NOT NULL,
  input_type TEXT NOT NULL,
  title TEXT,
  summary TEXT,
  confidence TEXT,
  confidence_score REAL,
  lat REAL,
  lon REAL,
  radius_m REAL,
  facts_json TEXT NOT NULL DEFAULT '[]',
  candidates_json TEXT NOT NULL DEFAULT '[]',
  sources_json TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE (normalized_query, input_type)
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  value TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'unknown',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE (network_id, value)
);
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name TEXT,
  port INTEGER,
  protocol TEXT,
  banner TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  observed_at TEXT NOT NULL,
  fetched_at TEXT,
  source TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_observations_network
  ON observations(network_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  status TEXT,
  last_checked TEXT,
  note TEXT
);
`;

const nowIso = () => new Date().toISOString();
const toJson = (value) => JSON.stringify(value ?? []);
const fromJson = (text, fallback) => {
  try {
    const parsed = JSON.parse(text ?? '');
    return parsed === null || parsed === undefined ? fallback : parsed;
  } catch {
    return fallback;
  }
};

function serializeNetwork(row) {
  if (!row) return null;
  return {
    id: row.id,
    normalizedQuery: row.normalized_query,
    inputType: row.input_type,
    title: row.title,
    summary: row.summary,
    confidence: row.confidence,
    confidenceScore: row.confidence_score,
    lat: row.lat,
    lon: row.lon,
    radiusM: row.radius_m,
    facts: fromJson(row.facts_json, []),
    candidates: fromJson(row.candidates_json, []),
    sources: fromJson(row.sources_json, []).map((s) => ({
      name: s.name,
      status: s.status ?? null,
      note: s.note ?? null,
    })),
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
  };
}

/**
 * Open (creating parent dirs and schema as needed) the inventory database.
 * Returns a handle with the persistence operations.
 */
export function openInventory(dbPath) {
  const resolved = resolveDbPath(dbPath);
  mkdirSync(dirname(resolved), { recursive: true });
  const db = new DatabaseSync(resolved);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);

  const upsertNetworkStmt = db.prepare(`
    INSERT INTO networks (
      normalized_query, input_type, title, summary, confidence,
      confidence_score, lat, lon, radius_m,
      facts_json, candidates_json, sources_json,
      first_seen, last_seen
    ) VALUES (
      @normalizedQuery, @inputType, @title, @summary, @confidence,
      @confidenceScore, @lat, @lon, @radiusM,
      @factsJson, @candidatesJson, @sourcesJson,
      @now, @now
    )
    ON CONFLICT (normalized_query, input_type) DO UPDATE SET
      title = excluded.title,
      summary = excluded.summary,
      confidence = excluded.confidence,
      confidence_score = excluded.confidence_score,
      lat = excluded.lat,
      lon = excluded.lon,
      radius_m = excluded.radius_m,
      facts_json = excluded.facts_json,
      candidates_json = excluded.candidates_json,
      sources_json = excluded.sources_json,
      last_seen = excluded.last_seen
    RETURNING id
  `);
  const upsertHostStmt = db.prepare(`
    INSERT INTO hosts (network_id, value, kind, first_seen, last_seen)
    VALUES (@networkId, @value, @kind, @now, @now)
    ON CONFLICT (network_id, value) DO UPDATE SET last_seen = excluded.last_seen
    RETURNING id
  `);
  const recordObservationStmt = db.prepare(`
    INSERT INTO observations (network_id, observed_at, fetched_at, source, detail_json)
    VALUES (@networkId, @observedAt, @fetchedAt, @source, @detailJson)
  `);
  const upsertSourceStmt = db.prepare(`
    INSERT INTO sources (name, status, last_checked, note)
    VALUES (@name, @status, @now, @note)
    ON CONFLICT (name) DO UPDATE SET
      status = excluded.status,
      last_checked = excluded.last_checked,
      note = excluded.note
  `);
  const getNetworkStmt = db.prepare('SELECT * FROM networks WHERE id = ?');
  const getNetworkByKeyStmt = db.prepare(
    'SELECT * FROM networks WHERE normalized_query = ? AND input_type = ?',
  );
  const listNetworksStmt = (limit) =>
    db.prepare(
      `SELECT * FROM networks ORDER BY last_seen DESC LIMIT ${Number.isInteger(limit) && limit > 0 ? Math.min(limit, 500) : 50}`,
    );
  const getHostsStmt = db.prepare(
    'SELECT * FROM hosts WHERE network_id = ? ORDER BY last_seen DESC',
  );
  const getObservationsStmt = db.prepare(
    'SELECT * FROM observations WHERE network_id = ? ORDER BY observed_at DESC LIMIT 50',
  );

  /**
   * Insert or refresh the dossier row for a network. Upserts by
   * (normalized_query, input_type); always bumps last_seen. Also upserts
   * any hosts carried by the dossier and refreshes per-source states.
   * Returns { id, created }.
   */
  function upsertNetwork(dossier) {
    if (!dossier || !dossier.normalizedQuery || !dossier.inputType) {
      throw new Error('upsertNetwork requires normalizedQuery and inputType');
    }
    const now = nowIso();
    const preexisting = getNetworkByKeyStmt.get(
      dossier.normalizedQuery,
      dossier.inputType,
    );
    const created = !preexisting;
    const row = upsertNetworkStmt.get({
      normalizedQuery: dossier.normalizedQuery,
      inputType: dossier.inputType,
      title: dossier.title ?? null,
      summary: dossier.summary ?? null,
      confidence: dossier.confidence ?? null,
      confidenceScore:
        typeof dossier.confidenceScore === 'number'
          ? dossier.confidenceScore
          : null,
      lat: typeof dossier.lat === 'number' ? dossier.lat : null,
      lon: typeof dossier.lon === 'number' ? dossier.lon : null,
      radiusM: typeof dossier.radiusM === 'number' ? dossier.radiusM : null,
      factsJson: toJson(dossier.facts),
      candidatesJson: toJson(dossier.candidates),
      sourcesJson: toJson(dossier.sources),
      now,
    });
    const networkId = row.id;
    for (const host of dossier.hosts ?? []) {
      if (!host || !host.value) continue;
      upsertHostStmt.get({
        networkId,
        value: String(host.value),
        kind: host.kind ?? 'unknown',
        now,
      });
    }
    for (const source of dossier.sources ?? []) {
      if (!source || !source.name) continue;
      upsertSourceStmt.get({
        name: source.name,
        status: source.status ?? null,
        note: source.note ?? null,
        now,
      });
    }
    return { id: networkId, created };
  }

  /** Append one observation row for a triangulation execution. */
  function recordObservation(networkId, { source = 'triangulate', detail = {}, fetchedAt = null } = {}) {
    if (!Number.isInteger(networkId)) {
      throw new Error('recordObservation requires a network id');
    }
    recordObservationStmt.run({
      networkId,
      observedAt: nowIso(),
      fetchedAt,
      source,
      detailJson: JSON.stringify(detail ?? {}),
    });
  }

  /** Latest networks first. */
  function listNetworks({ limit = 50 } = {}) {
    return listNetworksStmt(limit)
      .all()
      .map(serializeNetwork);
  }

  /** One network with its hosts and recent observations. */
  function getNetwork(id) {
    const network = serializeNetwork(getNetworkStmt.get(id));
    if (!network) return null;
    network.hosts = getHostsStmt.all(id).map((h) => ({
      id: h.id,
      value: h.value,
      kind: h.kind,
      firstSeen: h.first_seen,
      lastSeen: h.last_seen,
    }));
    network.observations = getObservationsStmt.all(id).map((o) => ({
      id: o.id,
      observedAt: o.observed_at,
      fetchedAt: o.fetched_at,
      source: o.source,
      detail: fromJson(o.detail_json, {}),
    }));
    return network;
  }

  function close() {
    db.close();
  }

  return { db, upsertNetwork, recordObservation, listNetworks, getNetwork, close };
}

let defaultInventory = null;

/** Lazily opened shared inventory (respects GEV_INVENTORY_DB). */
export function getDefaultInventory() {
  if (!defaultInventory) defaultInventory = openInventory();
  return defaultInventory;
}
