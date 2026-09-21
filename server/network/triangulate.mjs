/**
 * Passive network triangulation engine.
 *
 * Given an IP, hostname, BSSID, SSID or ASN, fans out to free public data
 * sources, converts each answer into a geo evidence circle
 * (lat, lon, radiusM, weight) and fuses them into one honest dossier:
 * weighted centroid, conflict detection between disagreeing strong
 * sources, and explicit confidence ceilings (anycast, CGNAT, no data).
 *
 * 100% passive: only public read APIs, reverse DNS through the system
 * resolver, and token-gated sources (WiGLE, OpenCelliD) that stay dormant
 * as `needs_token` without credentials. Nothing here probes, scans or
 * touches a third-party network.
 *
 * Every `triangulateNetwork()` call persists automatically: the dossier is
 * upserted into the SQLite inventory and one `observations` row records
 * the execution. `persistDossier()` is exported separately so tests can
 * exercise persistence without the network.
 */

import net from 'node:net';
import { lookup, reverse } from 'node:dns/promises';
import { getDefaultInventory, openInventory } from './inventory.mjs';

export const FETCH_TIMEOUT_MS = 5000;
const SOURCE_APP = 'gev-network-inventory';

/** Source reliability weights (higher = more trustworthy). */
export const SOURCE_WEIGHTS = Object.freeze({
  wigle: 1.0,
  opencellid: 0.8,
  beacondb: 0.7,
  peeringdb: 0.6,
  'ripestat-geoloc': 0.5,
  'ip-api': 0.4,
  rdns: 0.3,
});

/** Honest uncertainty radii per source, in meters. */
export const SOURCE_RADII_M = Object.freeze({
  wigle: 50,
  beacondb: 100,
  opencellid: 500,
  peeringdb: 10000,
  'ripestat-geoloc': 50000,
  'ip-api': 25000,
  rdns: 30000,
});

/** Well-known anycast addresses: not meaningfully geolocatable. */
const ANYCAST_IPS = new Set([
  '8.8.8.8',
  '8.8.4.4',
  '1.1.1.1',
  '1.0.0.1',
  '9.9.9.9',
  '149.112.112.112',
  '208.67.222.222',
  '208.67.220.220',
  '94.140.14.14',
  '94.140.15.15',
]);

/** Curated ISP hostname city codes (undns-style), Europe-focused. */
const CITY_CODES = Object.freeze({
  mad: { city: 'Madrid', lat: 40.4168, lon: -3.7038 },
  bcn: { city: 'Barcelona', lat: 41.3874, lon: 2.1686 },
  bar: { city: 'Barcelona', lat: 41.3874, lon: 2.1686 },
  agp: { city: 'Málaga', lat: 36.7213, lon: -4.4214 },
  svq: { city: 'Sevilla', lat: 37.3891, lon: -5.9845 },
  vlc: { city: 'Valencia', lat: 39.4699, lon: -0.3763 },
  bio: { city: 'Bilbao', lat: 43.263, lon: -2.9349 },
  lis: { city: 'Lisboa', lat: 38.7223, lon: -9.1393 },
  par: { city: 'París', lat: 48.8566, lon: 2.3522 },
  lon: { city: 'Londres', lat: 51.5074, lon: -0.1278 },
  ams: { city: 'Ámsterdam', lat: 52.3676, lon: 4.9041 },
  fra: { city: 'Fráncfort', lat: 50.1109, lon: 8.6821 },
  ber: { city: 'Berlín', lat: 52.52, lon: 13.405 },
  mil: { city: 'Milán', lat: 45.4642, lon: 9.19 },
  rom: { city: 'Roma', lat: 41.9028, lon: 12.4964 },
  vie: { city: 'Viena', lat: 48.2082, lon: 16.3738 },
  prg: { city: 'Praga', lat: 50.0755, lon: 14.4378 },
  waw: { city: 'Varsovia', lat: 52.2297, lon: 21.0122 },
  sto: { city: 'Estocolmo', lat: 59.3293, lon: 18.0686 },
  dublin: { city: 'Dublín', lat: 53.3498, lon: -6.2603 },
  dub: { city: 'Dublín', lat: 53.3498, lon: -6.2603 },
  bru: { city: 'Bruselas', lat: 50.8503, lon: 4.3517 },
  zur: { city: 'Zúrich', lat: 47.3769, lon: 8.5417 },
});

/**
 * Normalize a raw query into { inputType, normalizedQuery }.
 * inputType: 'ip' | 'hostname' | 'bssid' | 'ssid' | 'asn'
 */
export function normalizeQuery(raw) {
  const q = String(raw ?? '').trim();
  if (!q) throw new Error('Query must not be empty');

  const compact = q.replace(/\s+/g, '');
  const asnMatch = /^(?:as)?(\d+)$/i.exec(compact);
  if (asnMatch) {
    return { inputType: 'asn', normalizedQuery: `AS${asnMatch[1]}` };
  }

  const macHex = q.toUpperCase().replace(/[^0-9A-F]/g, '');
  if (/^[0-9A-F]{12}$/.test(macHex)) {
    return {
      inputType: 'bssid',
      normalizedQuery: macHex.match(/../g).join(':'),
    };
  }

  if (net.isIP(q)) {
    return { inputType: 'ip', normalizedQuery: q.toLowerCase() };
  }

  const lower = q.toLowerCase().replace(/\.$/, '');
  const label = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
  if (new RegExp(`^${label}(?:\\.${label})+$`).test(lower)) {
    return { inputType: 'hostname', normalizedQuery: lower };
  }
  // Single DNS-safe label without dots (e.g. intranet host) is a hostname.
  if (!/[\s]/.test(q) && new RegExp(`^${label}$`).test(lower)) {
    return { inputType: 'hostname', normalizedQuery: lower };
  }
  return { inputType: 'ssid', normalizedQuery: q };
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) // CGNAT
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l.startsWith('fc') || l.startsWith('fd');
  }
  return false;
}

function sourceStatus(name, status, note) {
  return { name, status, note: note ?? null };
}

function makeEvidence(source, lat, lon, detail) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  return {
    source,
    lat,
    lon,
    radiusM: SOURCE_RADII_M[source] ?? 25000,
    weight: SOURCE_WEIGHTS[source] ?? 0.3,
    observedAt: new Date().toISOString(),
    detail: detail ?? null,
  };
}

/** Fetch JSON with a short timeout; never throws — returns { ok, status, json }. */
async function fetchJson(url, { fetchImpl = globalThis.fetch, headers, method = 'GET', body } = {}) {
  try {
    const response = await fetchImpl(url, {
      method,
      headers,
      body,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { ok: response.ok, status: response.status, json };
  } catch (error) {
    return { ok: false, status: 0, json: null, error: error?.message };
  }
}

/** Wrap one source so a failure becomes a status, never an exception. */
async function runSource(name, fn) {
  try {
    return await fn();
  } catch (error) {
    return {
      status: sourceStatus(name, 'unavailable', error?.message ?? 'error'),
      evidence: [],
      facts: [],
    };
  }
}

// --- Source fetchers -------------------------------------------------------

async function sourceIpApi(ip, fetchImpl) {
  return runSource('ip-api', async () => {
    const { ok, json } = await fetchJson(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,query,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone`,
      { fetchImpl },
    );
    if (!ok || !json || json.status !== 'success') {
      return {
        status: sourceStatus('ip-api', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const evidence = [];
    const point = makeEvidence('ip-api', json.lat, json.lon, `${json.city ?? ''}, ${json.country ?? ''}`.trim());
    if (point) evidence.push(point);
    const facts = [
      ['Ciudad', [json.city, json.regionName, json.country].filter(Boolean).join(', ')],
      ['ISP', json.isp],
      ['Organización', json.org],
      ['ASN', json.as],
      ['Zona horaria', json.timezone],
    ]
      .filter(([, v]) => v)
      .map(([label, value]) => ({ label, value, source: 'ip-api' }));
    return { status: sourceStatus('ip-api', 'ok'), evidence, facts };
  });
}

async function sourceRipeStatGeoloc(ip, fetchImpl) {
  return runSource('ripestat-geoloc', async () => {
    const { ok, json } = await fetchJson(
      `https://stat.ripe.net/data/geoloc/data.json?resource=${encodeURIComponent(ip)}&sourceapp=${SOURCE_APP}`,
      { fetchImpl },
    );
    const locations = json?.data?.locations ?? [];
    if (!ok || !locations.length) {
      return {
        status: sourceStatus('ripestat-geoloc', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const evidence = [];
    const facts = [];
    for (const loc of locations.slice(0, 6)) {
      const point = makeEvidence(
        'ripestat-geoloc',
        Number(loc.latitude),
        Number(loc.longitude),
        `motor ${loc.engine ?? '?'}, ${loc.city ?? ''} ${loc.country ?? ''}`.trim(),
      );
      if (point) evidence.push(point);
    }
    facts.push({
      label: 'Geolocalización RIPEstat',
      value: `${locations.length} motores`,
      source: 'ripestat-geoloc',
    });
    return { status: sourceStatus('ripestat-geoloc', 'ok'), evidence, facts };
  });
}

async function sourceRipeStatPrefix(ip, fetchImpl) {
  return runSource('ripestat', async () => {
    const { ok, json } = await fetchJson(
      `https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}&sourceapp=${SOURCE_APP}`,
      { fetchImpl },
    );
    const data = json?.data;
    if (!ok || !data) {
      return {
        status: sourceStatus('ripestat', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const facts = [];
    const asns = (data.asns ?? []).map((a) => `AS${a.asn} (${a.holder ?? '?'})`);
    if (asns.length) facts.push({ label: 'ASN (BGP)', value: asns.join(', '), source: 'ripestat' });
    if (data.resource) facts.push({ label: 'Prefijo', value: data.resource, source: 'ripestat' });
    return {
      status: sourceStatus('ripestat', 'ok'),
      evidence: [],
      facts,
      asns: (data.asns ?? []).map((a) => a.asn),
    };
  });
}

async function sourceRipeStatAs(asn, fetchImpl) {
  return runSource('ripestat', async () => {
    const { ok, json } = await fetchJson(
      `https://stat.ripe.net/data/as-overview/data.json?resource=${encodeURIComponent(asn)}&sourceapp=${SOURCE_APP}`,
      { fetchImpl },
    );
    const data = json?.data;
    if (!ok || !data) {
      return {
        status: sourceStatus('ripestat', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const facts = [
      data.holder && { label: 'Titular', value: data.holder, source: 'ripestat' },
      data.block && { label: 'Bloque', value: `${data.block.resource} (${data.block.name ?? ''})`, source: 'ripestat' },
    ].filter(Boolean);
    return { status: sourceStatus('ripestat', 'ok'), evidence: [], facts };
  });
}

async function sourcePeeringDb(asnNumber, fetchImpl) {
  return runSource('peeringdb', async () => {
    const { ok, json } = await fetchJson(
      `https://www.peeringdb.com/api/net?asn=${encodeURIComponent(asnNumber)}`,
      { fetchImpl },
    );
    const nets = json?.data ?? [];
    if (!ok || !nets.length) {
      return {
        status: sourceStatus('peeringdb', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const netEntry = nets[0];
    const facts = [
      netEntry.name && { label: 'Red (PeeringDB)', value: netEntry.name, source: 'peeringdb' },
      netEntry.website && { label: 'Web', value: netEntry.website, source: 'peeringdb' },
    ].filter(Boolean);
    const evidence = [];
    const candidates = [];
    try {
      const facRes = await fetchJson(
        `https://www.peeringdb.com/api/netfac?net_id=${encodeURIComponent(netEntry.id)}`,
        { fetchImpl },
      );
      const facIds = [...new Set((facRes.json?.data ?? []).map((f) => f.fac_id))].slice(0, 5);
      for (const facId of facIds) {
        const fac = await fetchJson(`https://www.peeringdb.com/api/fac/${facId}`, { fetchImpl });
        const f = fac.json?.data?.[0];
        if (f && Number.isFinite(Number(f.latitude)) && Number.isFinite(Number(f.longitude))) {
          const lat = Number(f.latitude);
          const lon = Number(f.longitude);
          const point = makeEvidence('peeringdb', lat, lon, f.name ?? `facility ${facId}`);
          if (point) evidence.push(point);
          candidates.push({
            label: f.name ?? `Facility ${facId}`,
            detail: [f.city, f.country].filter(Boolean).join(', '),
            lat,
            lon,
            radiusM: SOURCE_RADII_M.peeringdb,
            source: 'peeringdb',
          });
        }
      }
    } catch {
      // facility enrichment is best-effort; the net record already stands
    }
    if (candidates.length) {
      facts.push({ label: 'Presencia', value: `${candidates.length} instalaciones`, source: 'peeringdb' });
    }
    return { status: sourceStatus('peeringdb', 'ok'), evidence, facts, candidates };
  });
}

async function sourceCrtSh(query, inputType, fetchImpl) {
  return runSource('crt.sh', async () => {
    if (inputType !== 'ip' && inputType !== 'hostname') {
      return { status: sourceStatus('crt.sh', 'not_applicable'), evidence: [], facts: [] };
    }
    const { ok, json } = await fetchJson(
      `https://crt.sh/?q=${encodeURIComponent(query)}&output=json`,
      { fetchImpl },
    );
    if (!ok || !Array.isArray(json) || !json.length) {
      return {
        status: sourceStatus('crt.sh', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
        hostnames: [],
      };
    }
    const names = [
      ...new Set(
        json
          .flatMap((c) => String(c.name_value ?? '').split('\n'))
          .map((n) => n.trim().toLowerCase().replace(/^\*\./, ''))
          .filter((n) => n && !n.includes('*')),
      ),
    ].slice(0, 12);
    const facts = names.length
      ? [{ label: 'Hostnames en CT logs', value: names.join(', '), source: 'crt.sh' }]
      : [];
    return {
      status: sourceStatus('crt.sh', 'ok'),
      evidence: [],
      facts,
      hostnames: names.map((value) => ({ value, kind: 'cert-hostname' })),
    };
  });
}

async function sourceReverseDns(ip, dnsImpl = { lookup, reverse }) {
  return runSource('rdns', async () => {
    if (!net.isIP(ip)) {
      return { status: sourceStatus('rdns', 'not_applicable'), evidence: [], facts: [] };
    }
    let names;
    try {
      names = await dnsImpl.reverse(ip);
    } catch {
      return { status: sourceStatus('rdns', 'empty', 'sin registro PTR'), evidence: [], facts: [] };
    }
    if (!names || !names.length) {
      return { status: sourceStatus('rdns', 'empty', 'sin registro PTR'), evidence: [], facts: [] };
    }
    const ptr = String(names[0]).toLowerCase().replace(/\.$/, '');
    const facts = [{ label: 'PTR', value: ptr, source: 'rdns' }];
    const evidence = [];
    const tokens = ptr.split(/[.-]/);
    for (const token of tokens) {
      const hit = CITY_CODES[token];
      if (hit) {
        const point = makeEvidence('rdns', hit.lat, hit.lon, `código "${token}" en ${ptr}`);
        if (point) evidence.push(point);
        facts.push({ label: 'Ciudad inferida (rDNS)', value: hit.city, source: 'rdns' });
        break;
      }
      const m = /^([a-z]{2,6})\d+$/.exec(token);
      if (m && CITY_CODES[m[1]]) {
        const c = CITY_CODES[m[1]];
        const point = makeEvidence('rdns', c.lat, c.lon, `código "${token}" en ${ptr}`);
        if (point) evidence.push(point);
        facts.push({ label: 'Ciudad inferida (rDNS)', value: c.city, source: 'rdns' });
        break;
      }
    }
    return {
      status: sourceStatus('rdns', 'ok'),
      evidence,
      facts,
      hostnames: [{ value: ptr, kind: 'ptr' }],
    };
  });
}

function wigleCredentials(env = process.env) {
  const name = env.WIGLE_API_NAME;
  const token = env.WIGLE_API_TOKEN;
  return name && token ? { name, token } : null;
}

async function sourceWigle({ bssid, ssid }, env, fetchImpl) {
  return runSource('wigle', async () => {
    const creds = wigleCredentials(env);
    if (!creds) {
      return {
        status: sourceStatus('wigle', 'needs_token', 'WIGLE_API_NAME/WIGLE_API_TOKEN'),
        evidence: [],
        facts: [],
      };
    }
    const params = new URLSearchParams();
    if (bssid) params.set('netid', bssid);
    else if (ssid) params.set('ssidlike', ssid);
    else return { status: sourceStatus('wigle', 'not_applicable'), evidence: [], facts: [] };
    const auth = Buffer.from(`${creds.name}:${creds.token}`).toString('base64');
    const { ok, json } = await fetchJson(
      `https://api.wigle.net/api/v2/network/search?${params}`,
      { fetchImpl, headers: { Authorization: `Basic ${auth}` } },
    );
    const results = json?.results ?? [];
    if (!ok || !results.length) {
      return {
        status: sourceStatus('wigle', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const r = results[0];
    const point = makeEvidence('wigle', Number(r.trilat), Number(r.trilong), r.ssid ?? bssid ?? '');
    const evidence = point ? [point] : [];
    const facts = [
      r.ssid && { label: 'SSID observado', value: r.ssid, source: 'wigle' },
      { label: 'Avistamientos WiGLE', value: String(json.totalResults ?? results.length), source: 'wigle' },
    ].filter(Boolean);
    return { status: sourceStatus('wigle', 'ok'), evidence, facts };
  });
}

async function sourceBeaconDb(bssid, fetchImpl) {
  return runSource('beacondb', async () => {
    if (!bssid) {
      return { status: sourceStatus('beacondb', 'not_applicable'), evidence: [], facts: [] };
    }
    const { ok, json } = await fetchJson('https://api.beacon.berylia.org/v1/geolocate', {
      fetchImpl,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ wifiAccessPoints: [{ macAddress: bssid }] }),
    });
    const loc = json?.location;
    if (!ok || !loc || !Number.isFinite(loc.lat) || !Number.isFinite(loc.lng)) {
      return {
        status: sourceStatus('beacondb', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const point = makeEvidence('beacondb', loc.lat, loc.lng, `precisión ±${loc.accuracy ?? '?'} m`);
    return {
      status: sourceStatus('beacondb', 'ok'),
      evidence: point ? [point] : [],
      facts: [],
    };
  });
}

async function sourceOpenCellId(point, env, fetchImpl) {
  return runSource('opencellid', async () => {
    const token = env.OPENCELLID_TOKEN;
    if (!token) {
      return {
        status: sourceStatus('opencellid', 'needs_token', 'OPENCELLID_TOKEN'),
        evidence: [],
        facts: [],
      };
    }
    if (!point) {
      return { status: sourceStatus('opencellid', 'not_applicable'), evidence: [], facts: [] };
    }
    const d = 0.05;
    const params = new URLSearchParams({
      key: token,
      lat1: String(point.lat - d),
      lon1: String(point.lon - d),
      lat2: String(point.lat + d),
      lon2: String(point.lon + d),
      format: 'json',
    });
    const { ok, json } = await fetchJson(`https://opencellid.org/ajax/getInArea?${params}`, { fetchImpl });
    const cells = Array.isArray(json) ? json : json?.cells ?? [];
    if (!ok || !cells.length) {
      return {
        status: sourceStatus('opencellid', ok ? 'empty' : 'unavailable'),
        evidence: [],
        facts: [],
      };
    }
    const c = cells[0];
    const tower = makeEvidence('opencellid', Number(c.lat), Number(c.lon), `torre ${c.radio ?? ''} ${c.mcc ?? ''}/${c.mnc ?? ''}`.trim());
    const facts = [
      { label: 'Torres cercanas (OpenCelliD)', value: String(cells.length), source: 'opencellid' },
    ];
    return { status: sourceStatus('opencellid', 'ok'), evidence: tower ? [tower] : [], facts };
  });
}

// --- Fusion ----------------------------------------------------------------

function haversineM(aLat, aLon, bLat, bLon) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(bLat - aLat);
  const dLon = toRad(bLon - aLon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(aLat)) * Math.cos(toRad(bLat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

const CONFLICT_DISTANCE_M = 100000; // strong sources in different cities

/**
 * Fuse geo evidence circles into one position.
 * Returns { lat, lon, radiusM, conflict, candidates, confidence, confidenceScore, notes[] }.
 */
export function fuseEvidence(evidence) {
  const points = (evidence ?? []).filter(
    (e) => Number.isFinite(e.lat) && Number.isFinite(e.lon),
  );
  const notes = [];
  if (!points.length) {
    return {
      lat: null,
      lon: null,
      radiusM: null,
      conflict: false,
      candidates: [],
      confidence: 'baja',
      confidenceScore: 0.15,
      notes: ['Sin evidencia geográfica de ninguna fuente.'],
    };
  }

  const strong = points.filter((p) => p.weight >= 0.5);
  const basis = strong.length ? strong : points;
  let conflict = false;
  const candidates = [];
  if (basis.length >= 2) {
    let maxDist = 0;
    for (let i = 0; i < basis.length; i++) {
      for (let j = i + 1; j < basis.length; j++) {
        maxDist = Math.max(
          maxDist,
          haversineM(basis[i].lat, basis[i].lon, basis[j].lat, basis[j].lon),
        );
      }
    }
    if (maxDist > CONFLICT_DISTANCE_M) {
      conflict = true;
      notes.push(
        `Fuentes de peso alto discrepan (${Math.round(maxDist / 1000)} km): no se promedia, se listan hipótesis.`,
      );
      for (const p of basis) {
        candidates.push({
          label: `${p.source}${p.detail ? ` — ${p.detail}` : ''}`,
          lat: p.lat,
          lon: p.lon,
          radiusM: p.radiusM,
          source: p.source,
        });
      }
    }
  }

  if (conflict) {
    const best = [...basis].sort((a, b) => b.weight - a.weight)[0];
    return {
      lat: best.lat,
      lon: best.lon,
      radiusM: best.radiusM,
      conflict: true,
      candidates,
      confidence: 'baja',
      confidenceScore: 0.3,
      notes,
    };
  }

  let wSum = 0;
  let latSum = 0;
  let lonSum = 0;
  let radiusSum = 0;
  let bestRadius = Infinity;
  for (const p of points) {
    const w = p.weight / Math.max(p.radiusM, 1) ** 2;
    wSum += w;
    latSum += p.lat * w;
    lonSum += p.lon * w;
    radiusSum += p.radiusM * w;
    bestRadius = Math.min(bestRadius, p.radiusM);
  }
  const lat = latSum / wSum;
  const lon = lonSum / wSum;
  const meanRadius = radiusSum / wSum;

  let spreadSum = 0;
  for (const p of points) {
    const w = p.weight / Math.max(p.radiusM, 1) ** 2;
    spreadSum += w * haversineM(lat, lon, p.lat, p.lon) ** 2;
  }
  const spread = Math.sqrt(spreadSum / wSum);
  const radiusM = Math.max(meanRadius, spread);

  const independent = new Set(points.map((p) => p.source)).size;
  const agreement = 1 / (1 + spread / 1000);
  const sourceTerm = Math.min(independent, 4) / 4;
  const radiusTerm =
    bestRadius <= 100 ? 1 : bestRadius <= 1000 ? 0.8 : bestRadius <= 25000 ? 0.5 : 0.3;
  let score = 0.5 * agreement + 0.3 * sourceTerm + 0.2 * radiusTerm;
  score = Math.min(1, Math.max(0, score));

  return {
    lat,
    lon,
    radiusM,
    conflict: false,
    candidates,
    confidence: score >= 0.7 ? 'alta' : score >= 0.4 ? 'media' : 'baja',
    confidenceScore: score,
    notes,
  };
}

// --- Dossier -----------------------------------------------------------------

/**
 * Triangulate a network identifier and persist the dossier.
 * Options (for tests): { fetch, dns, env, inventory, persist=true }.
 */
export async function triangulateNetwork(rawQuery, options = {}) {
  const {
    fetch: fetchImpl = globalThis.fetch,
    dns = { lookup, reverse },
    env = process.env,
    inventory = null,
    persist = true,
  } = options;

  const { inputType, normalizedQuery } = normalizeQuery(rawQuery);
  const fetchedAt = new Date().toISOString();
  const evidence = [];
  const facts = [];
  const sources = [];
  const candidates = [];
  const hostEntries = [{ value: normalizedQuery, kind: inputType }];
  const ceilings = [];

  const collect = (result) => {
    sources.push(result.status);
    for (const e of result.evidence ?? []) if (e) evidence.push(e);
    for (const f of result.facts ?? []) facts.push(f);
    for (const c of result.candidates ?? []) candidates.push(c);
    for (const h of result.hostnames ?? []) hostEntries.push(h);
    return result;
  };

  let targetIp = null;

  if (inputType === 'ip') {
    targetIp = normalizedQuery;
    if (ANYCAST_IPS.has(targetIp)) {
      ceilings.push('Dirección anycast: no acotable más allá de ciudad/PoP con fuentes gratuitas.');
      facts.push({ label: 'Nota', value: 'IP anycast (p. ej. DNS público)', source: 'local' });
    }
    if (isPrivateIp(targetIp)) {
      ceilings.push('Dirección privada/CGNAT: sin geolocalización pública posible.');
      facts.push({ label: 'Nota', value: 'IP privada o CGNAT (RFC1918 / 100.64.0.0/10)', source: 'local' });
    }
  }

  if (inputType === 'hostname') {
    try {
      const resolved = await dns.lookup(normalizedQuery);
      targetIp = resolved.address;
      facts.push({ label: 'Resolución DNS', value: `${normalizedQuery} → ${targetIp}`, source: 'dns' });
      hostEntries.push({ value: targetIp, kind: 'ip' });
      sources.push(sourceStatus('dns', 'ok'));
    } catch {
      sources.push(sourceStatus('dns', 'unavailable', 'no resuelve'));
    }
  }

  if (inputType === 'asn') {
    const asnNumber = normalizedQuery.replace(/^AS/i, '');
    const [ripeAs, pdb] = await Promise.all([
      sourceRipeStatAs(normalizedQuery, fetchImpl),
      sourcePeeringDb(asnNumber, fetchImpl),
    ]);
    collect(ripeAs);
    collect(pdb);
    const crt = await sourceCrtSh(normalizedQuery, inputType, fetchImpl);
    collect(crt);
  }

  if (inputType === 'bssid' || inputType === 'ssid') {
    const [wigle, beacon] = await Promise.all([
      sourceWigle(
        { bssid: inputType === 'bssid' ? normalizedQuery : null, ssid: inputType === 'ssid' ? normalizedQuery : null },
        env,
        fetchImpl,
      ),
      sourceBeaconDb(inputType === 'bssid' ? normalizedQuery : null, fetchImpl),
    ]);
    collect(wigle);
    collect(beacon);
  }

  if (targetIp && !isPrivateIp(targetIp)) {
    const [ipApi, geo, prefix, crt, rdns] = await Promise.all([
      sourceIpApi(targetIp, fetchImpl),
      sourceRipeStatGeoloc(targetIp, fetchImpl),
      sourceRipeStatPrefix(targetIp, fetchImpl),
      sourceCrtSh(targetIp, 'ip', fetchImpl),
      sourceReverseDns(targetIp, dns),
    ]);
    collect(ipApi);
    collect(geo);
    collect(prefix);
    collect(crt);
    collect(rdns);
    const asnNumber = (prefix.asns ?? [])[0];
    if (asnNumber) {
      const pdb = await sourcePeeringDb(String(asnNumber), fetchImpl);
      collect(pdb);
    }
  } else if (targetIp && isPrivateIp(targetIp)) {
    const rdns = await sourceReverseDns(targetIp, dns);
    collect(rdns);
  }

  // OpenCelliD is auxiliary: needs a first position to build a bbox around.
  const firstPoint = evidence.find((e) => Number.isFinite(e.lat));
  if (firstPoint) {
    const ocid = await sourceOpenCellId(firstPoint, env, fetchImpl);
    collect(ocid);
  } else {
    sources.push(sourceStatus('opencellid', env.OPENCELLID_TOKEN ? 'not_applicable' : 'needs_token'));
  }

  const fused = fuseEvidence(evidence);

  let confidence = fused.confidence;
  let confidenceScore = fused.confidenceScore;
  const notes = [...fused.notes, ...ceilings];
  if (ceilings.length && confidenceScore > 0.25) {
    confidenceScore = 0.25;
    confidence = 'baja';
    notes.push('Confianza limitada por techo honesto (anycast/CGNAT/privada).');
  }
  const strongSources = new Set(evidence.filter((e) => e.weight >= 0.5).map((e) => e.source));
  if (!strongSources.size && confidenceScore > 0.4) {
    confidenceScore = 0.4;
    confidence = 'baja';
    notes.push('Sin fuentes de peso alto: confianza capada.');
  }

  const where = fused.lat !== null
    ? `cerca de ${fused.lat.toFixed(4)}, ${fused.lon.toFixed(4)} (±${Math.round(fused.radiusM)} m)`
    : 'sin posición determinada';
  const okSources = sources.filter((s) => s.status === 'ok').length;
  const titleBits = {
    ip: `IP ${normalizedQuery}`,
    hostname: `Host ${normalizedQuery}`,
    bssid: `BSSID ${normalizedQuery}`,
    ssid: `SSID "${normalizedQuery}"`,
    asn: `ASN ${normalizedQuery}`,
  };
  const title = `${titleBits[inputType]} — ${where}`;
  const summary =
    `Triangulación pasiva de ${normalizedQuery} (${inputType}): ` +
    `${okSources}/${sources.length} fuentes con datos, ${evidence.length} evidencias geográficas. ` +
    `Confianza ${confidence} (${confidenceScore.toFixed(2)}).` +
    (notes.length ? ` Notas: ${notes.join(' ')}` : '');

  const dossier = {
    query: String(rawQuery ?? ''),
    normalizedQuery,
    inputType,
    title,
    summary,
    confidence,
    confidenceScore,
    lat: fused.lat,
    lon: fused.lon,
    radiusM: fused.radiusM,
    conflict: fused.conflict,
    facts,
    evidence: evidence.map((e) => ({
      source: e.source,
      lat: e.lat,
      lon: e.lon,
      radiusM: e.radiusM,
      weight: e.weight,
      observedAt: e.observedAt,
      detail: e.detail,
    })),
    candidates: [...fused.candidates, ...candidates],
    sources,
    hosts: hostEntries,
    fetchedAt,
  };

  if (persist) persistDossier(dossier, inventory);
  return dossier;
}

/** Persist a dossier: upsert the network row + one observation per execution. */
export function persistDossier(dossier, inventory = null) {
  const inv = inventory ?? getDefaultInventory();
  const { id } = inv.upsertNetwork(dossier);
  inv.recordObservation(id, {
    source: 'triangulate',
    fetchedAt: dossier.fetchedAt ?? null,
    detail: {
      normalizedQuery: dossier.normalizedQuery,
      inputType: dossier.inputType,
      confidence: dossier.confidence,
      confidenceScore: dossier.confidenceScore,
      sourceStates: (dossier.sources ?? []).map((s) => `${s.name}:${s.status}`),
    },
  });
  return id;
}

/** Compact, agent-friendly rendering of a dossier (for MCP responses). */
export function summarizeDossier(dossier, { maxEvidence = 10, maxFacts = 25 } = {}) {
  return {
    query: dossier.query,
    normalizedQuery: dossier.normalizedQuery,
    inputType: dossier.inputType,
    title: dossier.title,
    summary: dossier.summary,
    confidence: dossier.confidence,
    confidenceScore: dossier.confidenceScore,
    lat: dossier.lat,
    lon: dossier.lon,
    radiusM: dossier.radiusM,
    conflict: dossier.conflict,
    facts: (dossier.facts ?? []).slice(0, maxFacts),
    evidence: (dossier.evidence ?? []).slice(0, maxEvidence),
    candidates: dossier.candidates ?? [],
    sources: dossier.sources ?? [],
    fetchedAt: dossier.fetchedAt,
  };
}

/** Open a throwaway inventory (used by callers that manage the lifecycle). */
export function openTestInventory(dbPath) {
  return openInventory(dbPath);
}
