/**
 * Active HTTP, HTTPS, TLS & RTSP Fingerprinting Engine.
 * Inspects exposed endpoints, gathers banners, certificates, SANs, and security headers.
 */

import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import net from 'node:net';
import crypto from 'node:crypto';
import { getDefaultReconDb } from './db.mjs';

const PROBE_TIMEOUT_MS = 4000;

/** Extract HTML <title> tag if present */
function extractTitle(body) {
  if (!body || typeof body !== 'string') return null;
  const match = body.match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim() : null;
}

/** Probe HTTP or HTTPS endpoint */
async function probeHttpEndpoint(host, port, isHttps = false) {
  return new Promise((resolve) => {
    const protocol = isHttps ? 'https' : 'http';
    const lib = isHttps ? https : http;

    const req = lib.request(
      {
        hostname: host,
        port: Number(port),
        method: 'GET',
        path: '/',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; GodsEyeView-ActiveRecon/1.0)',
          Accept: '*/*',
        },
        rejectUnauthorized: false,
        timeout: PROBE_TIMEOUT_MS,
      },
      (res) => {
        let rawBody = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (rawBody.length < 32768) {
            rawBody += chunk;
          }
        });
        res.on('end', () => {
          const headers = res.headers || {};
          const securityHeaders = {
            hsts: headers['strict-transport-security'] || null,
            csp: headers['content-security-policy'] || null,
            x_frame_options: headers['x-frame-options'] || null,
            x_content_type_options: headers['x-content-type-options'] || null,
            cors: headers['access-control-allow-origin'] || null,
          };

          resolve({
            ok: true,
            port,
            protocol,
            statusCode: res.statusCode,
            serverBanner: headers['server'] || headers['x-powered-by'] || null,
            pageTitle: extractTitle(rawBody),
            authHeader: headers['www-authenticate'] || null,
            securityHeaders,
            rawHeaders: headers,
          });
        });
      },
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, port, protocol, error: 'TIMEOUT' });
    });

    req.on('error', (err) => {
      resolve({ ok: false, port, protocol, error: err.code || err.message });
    });

    req.end();
  });
}

/** Probe TLS certificate directly (extract SANs, Issuer, Validity) */
async function probeTlsCertificate(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: PROBE_TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({ ok: false, error: 'NO_CERTIFICATE' });
        }

        let sans = [];
        if (cert.subjectaltname) {
          sans = cert.subjectaltname
            .split(',')
            .map((s) => s.trim().replace(/^DNS:/, ''))
            .filter(Boolean);
        }

        resolve({
          ok: true,
          subject: cert.subject ? cert.subject.CN || JSON.stringify(cert.subject) : null,
          issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN || JSON.stringify(cert.issuer) : null,
          sans,
          validFrom: cert.valid_from ? new Date(cert.valid_from).getTime() : null,
          validTo: cert.valid_to ? new Date(cert.valid_to).getTime() : null,
          fingerprint: cert.fingerprint256 || cert.fingerprint,
        });
      },
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, error: 'TLS_TIMEOUT' });
    });

    socket.on('error', (err) => {
      resolve({ ok: false, error: err.code || err.message });
    });
  });
}

/** Probe RTSP camera / streaming service */
async function probeRtspEndpoint(host, port = 554) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(PROBE_TIMEOUT_MS);

    socket.connect(port, host, () => {
      const probeMessage = `OPTIONS rtsp://${host}:${port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: GodsEyeView-Recon\r\n\r\n`;
      socket.write(probeMessage);
    });

    let buffer = '';
    socket.on('data', (data) => {
      buffer += data.toString('utf8');
      if (buffer.includes('\r\n\r\n')) {
        socket.destroy();
      }
    });

    socket.on('close', () => {
      if (!buffer) {
        return resolve({ ok: false, port, protocol: 'rtsp', error: 'EMPTY_RESPONSE' });
      }

      const lines = buffer.split('\r\n');
      const statusLine = lines[0] || '';
      const statusMatch = statusLine.match(/RTSP\/\d\.\d\s+(\d+)/i);
      const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : null;

      let serverBanner = null;
      let publicMethods = null;

      for (const line of lines) {
        if (/^Server:/i.test(line)) serverBanner = line.replace(/^Server:\s*/i, '').trim();
        if (/^Public:/i.test(line)) publicMethods = line.replace(/^Public:\s*/i, '').trim();
      }

      resolve({
        ok: true,
        port,
        protocol: 'rtsp',
        statusCode,
        serverBanner: serverBanner || (publicMethods ? `RTSP (${publicMethods})` : 'RTSP Server'),
        authHeader: lines.find((l) => /^WWW-Authenticate:/i.test(l)) || null,
        rawHeaders: { publicMethods, statusLine },
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ ok: false, port, protocol: 'rtsp', error: 'TIMEOUT' });
    });

    socket.on('error', (err) => {
      resolve({ ok: false, port, protocol: 'rtsp', error: err.code || err.message });
    });
  });
}

/**
 * Perform comprehensive active fingerprinting on a target host
 * @param {Object} options
 * @param {string} options.host - Target IP or domain
 * @param {string} [options.targetId] - Target ID
 * @param {string} [options.targetType] - 'cctv', 'radio_stream', 'server', 'ip'
 * @param {number[]} [options.ports] - Optional custom ports to probe
 * @param {ReconDatabase} [options.db] - Optional custom db instance
 */
export async function fingerprintTarget({
  host,
  targetId = null,
  targetType = 'server',
  ports = [80, 443, 554, 8080, 8443],
  db = null,
  probeHttpFn = probeHttpEndpoint,
  probeRtspFn = probeRtspEndpoint,
  probeTlsFn = probeTlsCertificate,
}) {
  const reconDb = db || getDefaultReconDb();
  const id = targetId || `target:${host}`;

  // Upsert target in database
  reconDb.upsertTarget({
    id,
    targetType,
    host,
    tags: [targetType, 'fingerprinted'],
  });

  const results = [];

  for (const port of ports) {
    if (port === 554 || port === 8554) {
      const rtspRes = await probeRtspFn(host, port);
      if (rtspRes.ok) {
        reconDb.saveFingerprint({
          targetId: id,
          port,
          protocol: 'rtsp',
          statusCode: rtspRes.statusCode,
          serverBanner: rtspRes.serverBanner,
          authHeader: rtspRes.authHeader,
          rawHeaders: rtspRes.rawHeaders,
        });
        results.push(rtspRes);
      }
      continue;
    }

    const isTlsPort = port === 443 || port === 8443;
    const httpRes = await probeHttpFn(host, port, isTlsPort);

    let tlsData = null;
    if (isTlsPort && httpRes.ok) {
      tlsData = await probeTlsFn(host, port);
    }

    if (httpRes.ok) {
      reconDb.saveFingerprint({
        targetId: id,
        port,
        protocol: httpRes.protocol,
        statusCode: httpRes.statusCode,
        serverBanner: httpRes.serverBanner,
        pageTitle: httpRes.pageTitle,
        authHeader: httpRes.authHeader,
        securityHeaders: httpRes.securityHeaders,
        tlsSubject: tlsData?.subject || null,
        tlsIssuer: tlsData?.issuer || null,
        tlsSans: tlsData?.sans || [],
        tlsValidTo: tlsData?.validTo || null,
        rawHeaders: httpRes.rawHeaders,
      });

      results.push({
        ...httpRes,
        tls: tlsData,
      });
    }
  }

  return {
    targetId: id,
    host,
    fingerprints: results,
    savedCount: results.length,
  };
}
