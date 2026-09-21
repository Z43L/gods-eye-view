/**
 * Connect/Vite middleware exposing Active Reconnaissance & SQLite persistence endpoints.
 */

import { getDefaultReconDb } from '../recon/db.mjs';
import { fingerprintTarget } from '../recon/fingerprint.mjs';
import { runTraceroute } from '../recon/traceroute.mjs';
import { runDnsRecon } from '../recon/dnsRecon.mjs';

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 1e6) {
        req.destroy();
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.statusCode = statusCode;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(data));
}

export function reconProxy() {
  const db = getDefaultReconDb();

  return {
    name: 'gev-recon-provider',
    configureServer(server) {
      // 1. Fingerprint endpoint
      server.middlewares.use('/api/recon/fingerprint', async (req, res, next) => {
        if (req.method !== 'POST') return next();
        try {
          const body = await readJsonBody(req);
          if (!body.host) {
            return sendJson(res, 400, { error: 'Missing required field: host' });
          }
          const result = await fingerprintTarget({
            host: body.host,
            targetId: body.targetId,
            targetType: body.targetType || 'server',
            ports: body.ports || [80, 443, 554, 8080, 8443],
            db,
          });
          sendJson(res, 200, { ok: true, ...result });
        } catch (error) {
          sendJson(res, 500, { ok: false, error: error.message });
        }
      });

      // 2. Traceroute endpoint
      server.middlewares.use('/api/recon/traceroute', async (req, res, next) => {
        if (req.method !== 'POST') return next();
        try {
          const body = await readJsonBody(req);
          if (!body.target) {
            return sendJson(res, 400, { error: 'Missing required field: target' });
          }
          const result = await runTraceroute({
            target: body.target,
            targetId: body.targetId,
            maxHops: body.maxHops || 20,
            db,
          });
          sendJson(res, 200, { ok: true, ...result });
        } catch (error) {
          sendJson(res, 500, { ok: false, error: error.message });
        }
      });

      // 3. DNS Recon endpoint
      server.middlewares.use('/api/recon/dns', async (req, res, next) => {
        if (req.method !== 'POST') return next();
        try {
          const body = await readJsonBody(req);
          if (!body.domain) {
            return sendJson(res, 400, { error: 'Missing required field: domain' });
          }
          const result = await runDnsRecon({
            domain: body.domain,
            targetId: body.targetId,
            db,
          });
          sendJson(res, 200, { ok: true, ...result });
        } catch (error) {
          sendJson(res, 500, { ok: false, error: error.message });
        }
      });

      // 4. Get target dossier or list targets
      server.middlewares.use('/api/recon/target', (req, res, next) => {
        if (req.method !== 'GET') return next();
        const url = new URL(req.url, 'http://localhost');
        const targetId = url.searchParams.get('id');
        if (!targetId) {
          return sendJson(res, 400, { error: 'Missing query parameter: id' });
        }
        const dossier = db.getFullDossier(targetId);
        if (!dossier) {
          return sendJson(res, 404, { error: 'Target not found in SQLite store' });
        }
        sendJson(res, 200, { ok: true, ...dossier });
      });

      // 5. List targets
      server.middlewares.use('/api/recon/targets', (req, res, next) => {
        if (req.method !== 'GET') return next();
        const url = new URL(req.url, 'http://localhost');
        const limit = parseInt(url.searchParams.get('limit') || '50', 10);
        const tag = url.searchParams.get('tag');
        const targets = db.listTargets({ limit, tag });
        sendJson(res, 200, { ok: true, count: targets.length, targets });
      });
    },
  };
}
