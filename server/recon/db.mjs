/**
 * SQLite persistence layer for Active Reconnaissance & Threat Intelligence.
 * Uses Node.js native `node:sqlite` (DatabaseSync) with zero external binary dependencies.
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, '..', '..');

export const DEFAULT_RECON_DB_PATH = join(REPO_ROOT, '.gev-cache', 'recon.db');

export function resolveReconDbPath(customPath) {
  if (customPath) return customPath;
  if (process.env.GEV_RECON_DB) return process.env.GEV_RECON_DB;
  return DEFAULT_RECON_DB_PATH;
}

const RECON_SCHEMA = `
CREATE TABLE IF NOT EXISTS targets (
  id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL,
  host TEXT NOT NULL,
  ip TEXT,
  latitude REAL,
  longitude REAL,
  first_seen INTEGER NOT NULL,
  last_scanned INTEGER NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS http_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  status_code INTEGER,
  server_banner TEXT,
  page_title TEXT,
  favicon_hash TEXT,
  auth_header TEXT,
  security_headers_json TEXT NOT NULL DEFAULT '{}',
  tls_subject TEXT,
  tls_issuer TEXT,
  tls_sans_json TEXT NOT NULL DEFAULT '[]',
  tls_valid_to INTEGER,
  raw_headers_json TEXT NOT NULL DEFAULT '{}',
  scanned_at INTEGER NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS network_traces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  destination_ip TEXT NOT NULL,
  total_hops INTEGER NOT NULL,
  total_rtt_ms REAL,
  hops_json TEXT NOT NULL DEFAULT '[]',
  cable_correlations_json TEXT NOT NULL DEFAULT '[]',
  traced_at INTEGER NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  record_type TEXT NOT NULL,
  record_value TEXT NOT NULL,
  ttl INTEGER,
  axfr_vulnerable INTEGER DEFAULT 0,
  discovered_at INTEGER NOT NULL,
  FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host);
CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets(ip);
CREATE INDEX IF NOT EXISTS idx_http_target ON http_fingerprints(target_id);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_traces_target ON network_traces(target_id);
`;

export class ReconDatabase {
  constructor(dbPath) {
    this.dbPath = resolveReconDbPath(dbPath);
    mkdirSync(dirname(this.dbPath), { recursive: true });
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(RECON_SCHEMA);
  }

  close() {
    this.db.close();
  }

  /** Upsert a reconnaissance target */
  upsertTarget({ id, targetType, host, ip = null, latitude = null, longitude = null, tags = [] }) {
    const now = Date.now();
    const existing = this.getTarget(id);
    const firstSeen = existing ? existing.first_seen : now;
    const tagsJson = JSON.stringify(tags || []);

    const stmt = this.db.prepare(`
      INSERT INTO targets (id, target_type, host, ip, latitude, longitude, first_seen, last_scanned, tags_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        target_type = excluded.target_type,
        host = excluded.host,
        ip = COALESCE(excluded.ip, targets.ip),
        latitude = COALESCE(excluded.latitude, targets.latitude),
        longitude = COALESCE(excluded.longitude, targets.longitude),
        last_scanned = excluded.last_scanned,
        tags_json = excluded.tags_json
    `);

    stmt.run(id, targetType, host, ip, latitude, longitude, firstSeen, now, tagsJson);
    return this.getTarget(id);
  }

  /** Retrieve target by ID */
  getTarget(id) {
    const stmt = this.db.prepare(`SELECT * FROM targets WHERE id = ?`);
    const row = stmt.get(id);
    if (!row) return null;
    return {
      ...row,
      tags: JSON.parse(row.tags_json || '[]'),
    };
  }

  /** List targets with optional filter & limit */
  listTargets({ limit = 50, tag = null } = {}) {
    let query = `SELECT * FROM targets ORDER BY last_scanned DESC LIMIT ?`;
    let stmt = this.db.prepare(query);
    let rows = stmt.all(limit);

    if (tag) {
      rows = rows.filter((r) => {
        const tags = JSON.parse(r.tags_json || '[]');
        return tags.includes(tag);
      });
    }

    return rows.map((r) => ({
      ...r,
      tags: JSON.parse(r.tags_json || '[]'),
    }));
  }

  /** Save HTTP / TLS / RTSP fingerprint */
  saveFingerprint({
    targetId,
    port,
    protocol,
    statusCode = null,
    serverBanner = null,
    pageTitle = null,
    faviconHash = null,
    authHeader = null,
    securityHeaders = {},
    tlsSubject = null,
    tlsIssuer = null,
    tlsSans = [],
    tlsValidTo = null,
    rawHeaders = {},
  }) {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT INTO http_fingerprints (
        target_id, port, protocol, status_code, server_banner, page_title,
        favicon_hash, auth_header, security_headers_json, tls_subject,
        tls_issuer, tls_sans_json, tls_valid_to, raw_headers_json, scanned_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      targetId,
      port,
      protocol,
      statusCode,
      serverBanner,
      pageTitle,
      faviconHash,
      authHeader,
      JSON.stringify(securityHeaders || {}),
      tlsSubject,
      tlsIssuer,
      JSON.stringify(tlsSans || []),
      tlsValidTo,
      JSON.stringify(rawHeaders || {}),
      now,
    );

    return this.getFingerprints(targetId);
  }

  /** Get all fingerprints for a target */
  getFingerprints(targetId) {
    const stmt = this.db.prepare(`
      SELECT * FROM http_fingerprints WHERE target_id = ? ORDER BY scanned_at DESC
    `);
    const rows = stmt.all(targetId);
    return rows.map((r) => ({
      ...r,
      security_headers: JSON.parse(r.security_headers_json || '{}'),
      tls_sans: JSON.parse(r.tls_sans_json || '[]'),
      raw_headers: JSON.parse(r.raw_headers_json || '{}'),
    }));
  }

  /** Save network trace (Traceroute) */
  saveNetworkTrace({
    targetId,
    destinationIp,
    totalHops,
    totalRttMs,
    hops = [],
    cableCorrelations = [],
  }) {
    const now = Date.now();
    const stmt = this.db.prepare(`
      INSERT INTO network_traces (
        target_id, destination_ip, total_hops, total_rtt_ms, hops_json, cable_correlations_json, traced_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      targetId,
      destinationIp,
      totalHops,
      totalRttMs,
      JSON.stringify(hops || []),
      JSON.stringify(cableCorrelations || []),
      now,
    );

    return this.getNetworkTraces(targetId);
  }

  /** Get network traces for a target */
  getNetworkTraces(targetId) {
    const stmt = this.db.prepare(`
      SELECT * FROM network_traces WHERE target_id = ? ORDER BY traced_at DESC
    `);
    const rows = stmt.all(targetId);
    return rows.map((r) => ({
      ...r,
      hops: JSON.parse(r.hops_json || '[]'),
      cable_correlations: JSON.parse(r.cable_correlations_json || '[]'),
    }));
  }

  /** Save DNS records batch */
  saveDnsRecords(targetId, domain, records, axfrVulnerable = 0) {
    const now = Date.now();
    // Delete existing records for this domain to keep fresh snapshot
    const delStmt = this.db.prepare(`DELETE FROM dns_records WHERE target_id = ? AND domain = ?`);
    delStmt.run(targetId, domain);

    const insertStmt = this.db.prepare(`
      INSERT INTO dns_records (target_id, domain, record_type, record_value, ttl, axfr_vulnerable, discovered_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const rec of records) {
      insertStmt.run(
        targetId,
        domain,
        rec.type,
        String(rec.value),
        rec.ttl || null,
        axfrVulnerable ? 1 : 0,
        now,
      );
    }

    return this.getDnsRecords(targetId);
  }

  /** Get DNS records for a target */
  getDnsRecords(targetId) {
    const stmt = this.db.prepare(`
      SELECT * FROM dns_records WHERE target_id = ? ORDER BY record_type ASC, record_value ASC
    `);
    return stmt.all(targetId);
  }

  /** Get full aggregated dossier for a target */
  getFullDossier(targetId) {
    const target = this.getTarget(targetId);
    if (!target) return null;

    return {
      target,
      fingerprints: this.getFingerprints(targetId),
      network_traces: this.getNetworkTraces(targetId),
      dns_records: this.getDnsRecords(targetId),
    };
  }
}

let defaultInstance = null;

export function getDefaultReconDb() {
  if (!defaultInstance) {
    defaultInstance = new ReconDatabase();
  }
  return defaultInstance;
}
