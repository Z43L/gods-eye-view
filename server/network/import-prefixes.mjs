/**
 * Bulk-import the BGP announced prefixes of an ASN into the SQLite network
 * inventory ("poco a poco" mapping). 100% passive: only RIPEstat's public
 * API, no packets sent to the target network.
 *
 * Usage: node server/network/import-prefixes.mjs AS12338 [--db <path>]
 *
 * Each prefix becomes a network row (input_type 'cidr') with one
 * 'bgp-announced-prefix' observation. Re-running is idempotent: rows are
 * upserted by (prefix, 'cidr') and last_seen is refreshed.
 */

import { getDefaultInventory, openInventory } from './inventory.mjs';

const RIPESTAT = 'https://stat.ripe.net/data';

async function fetchJson(url, timeoutMs = 15000) {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': 'gev-network-inventory' },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return res.json();
}

function normalizeAsn(raw) {
  const m = String(raw || '').trim().toUpperCase().match(/^(?:AS)?(\d+)$/);
  if (!m) throw new Error(`Not an ASN: ${raw} (expected like AS12338)`);
  return `AS${m[1]}`;
}

export async function importPrefixes(asnRaw, { inventory = null } = {}) {
  const asn = normalizeAsn(asnRaw);
  const inv = inventory ?? getDefaultInventory();
  const closeWhenDone = !inventory;

  const [prefixesJson, overviewJson] = await Promise.all([
    fetchJson(`${RIPESTAT}/announced-prefixes/data.json?resource=${encodeURIComponent(asn)}`),
    fetchJson(`${RIPESTAT}/as-overview/data.json?resource=${encodeURIComponent(asn)}`).catch(() => null),
  ]);

  const prefixes = (prefixesJson?.data?.prefixes ?? []).map((p) => p.prefix).filter(Boolean);
  const holder = overviewJson?.data?.holder ?? null;

  let created = 0;
  let updated = 0;
  for (const prefix of prefixes) {
    const isV6 = prefix.includes(':');
    const dossier = {
      normalizedQuery: prefix,
      inputType: 'cidr',
      title: `Prefijo ${prefix} — ${asn}`,
      summary:
        `Prefijo BGP ${isV6 ? 'IPv6' : 'IPv4'} anunciado por ${asn}` +
        (holder ? ` (${holder})` : '') +
        '. Dato público de RIPEstat; sin geolocalización.',
      confidence: 'baja',
      confidenceScore: 0.1,
      lat: null,
      lon: null,
      radiusM: null,
      facts: [
        { label: 'ASN', value: asn, source: 'ripestat' },
        ...(holder ? [{ label: 'Titular', value: holder, source: 'ripestat' }] : []),
        { label: 'Prefijo', value: prefix, source: 'ripestat' },
        { label: 'Familia', value: isV6 ? 'IPv6' : 'IPv4', source: 'ripestat' },
      ],
      evidence: [],
      candidates: [],
      sources: [{ name: 'ripestat', status: 'ok' }],
    };
    const { id, created: wasCreated } = inv.upsertNetwork(dossier);
    if (wasCreated) created++;
    else updated++;
    inv.recordObservation(id, {
      source: 'ripestat',
      detail: { kind: 'bgp-announced-prefix', asn, prefix, holder },
    });
  }

  if (closeWhenDone) inv.close();
  return { asn, holder, total: prefixes.length, created, updated };
}

const isMain = process.argv[1]?.endsWith('import-prefixes.mjs');
if (isMain) {
  const args = process.argv.slice(2);
  const asnArg = args.find((a) => !a.startsWith('--'));
  const dbIdx = args.indexOf('--db');
  if (!asnArg) {
    console.error('Usage: node server/network/import-prefixes.mjs AS12338 [--db <path>]');
    process.exit(1);
  }
  const inventory = dbIdx >= 0 && args[dbIdx + 1] ? openInventory(args[dbIdx + 1]) : null;
  try {
    const result = await importPrefixes(asnArg, inventory ? { inventory } : {});
    console.log(
      `${result.asn}${result.holder ? ` (${result.holder})` : ''}: ` +
        `${result.total} prefijos (${result.created} nuevos, ${result.updated} actualizados)`,
    );
  } catch (err) {
    console.error(`import-prefixes failed: ${err.message}`);
    process.exit(1);
  } finally {
    inventory?.close();
  }
}
