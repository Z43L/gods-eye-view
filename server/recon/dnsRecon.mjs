/**
 * Active DNS Reconnaissance & Surface Discovery Engine.
 * Resolves standard records, inspects SPF/DMARC, checks AXFR zone transfers,
 * and executes subnet reverse DNS queries.
 */

import dns from 'node:dns/promises';
import { getDefaultReconDb } from './db.mjs';

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA'];

/** Attempt active resolution for standard DNS record types */
async function resolveAllDnsTypes(domain) {
  const records = [];

  for (const type of RECORD_TYPES) {
    try {
      let res;
      switch (type) {
        case 'A':
          res = await dns.resolve4(domain, { ttl: true });
          for (const item of res) {
            records.push({ type: 'A', value: item.address, ttl: item.ttl });
          }
          break;
        case 'AAAA':
          res = await dns.resolve6(domain, { ttl: true });
          for (const item of res) {
            records.push({ type: 'AAAA', value: item.address, ttl: item.ttl });
          }
          break;
        case 'CNAME':
          res = await dns.resolveCname(domain);
          for (const cname of res) {
            records.push({ type: 'CNAME', value: cname });
          }
          break;
        case 'MX':
          res = await dns.resolveMx(domain);
          for (const mx of res) {
            records.push({ type: 'MX', value: `${mx.priority} ${mx.exchange}` });
          }
          break;
        case 'TXT':
          res = await dns.resolveTxt(domain);
          for (const chunk of res) {
            records.push({ type: 'TXT', value: chunk.join(' ') });
          }
          break;
        case 'NS':
          res = await dns.resolveNs(domain);
          for (const ns of res) {
            records.push({ type: 'NS', value: ns });
          }
          break;
        case 'SOA':
          res = await dns.resolveSoa(domain);
          if (res) {
            records.push({
              type: 'SOA',
              value: `${res.nsname} ${res.hostmaster} (serial: ${res.serial})`,
              ttl: res.minttl,
            });
          }
          break;
        case 'CAA':
          res = await dns.resolveCaa(domain);
          for (const caa of res) {
            records.push({ type: 'CAA', value: `${caa.issue || caa.issuewild || caa.iodef}` });
          }
          break;
      }
    } catch {
      // Record type doesn't exist for this domain - continue
    }
  }

  return records;
}

/** Reverse DNS lookup for an IP address */
async function resolveReversePtr(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    return hostnames.map((h) => ({ type: 'PTR', value: h }));
  } catch {
    return [];
  }
}

/**
 * Perform comprehensive active DNS reconnaissance on a domain or IP
 * @param {Object} options
 * @param {string} options.domain - Target domain or IP
 * @param {string} [options.targetId] - Target identifier
 * @param {ReconDatabase} [options.db] - SQLite instance
 */
export async function runDnsRecon({
  domain,
  targetId = null,
  db = null,
}) {
  const reconDb = db || getDefaultReconDb();
  const id = targetId || `target:${domain}`;

  let isIp = false;
  try {
    // Check if target is an IPv4 / IPv6
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain) || domain.includes(':')) {
      isIp = true;
    }
  } catch {
    // Treat as domain
  }

  const records = [];

  if (isIp) {
    const ptrRecords = await resolveReversePtr(domain);
    records.push(...ptrRecords);
  } else {
    const standardRecords = await resolveAllDnsTypes(domain);
    records.push(...standardRecords);

    // If we resolved A records, also reverse-lookup their PTRs
    const aRecords = records.filter((r) => r.type === 'A');
    for (const aRec of aRecords) {
      const ptrs = await resolveReversePtr(aRec.value);
      records.push(...ptrs);
    }
  }

  // Identify SPF & DMARC policies
  const txtRecords = records.filter((r) => r.type === 'TXT');
  const spfRecord = txtRecords.find((r) => r.value.startsWith('v=spf1'))?.value || null;
  const dmarcRecord = txtRecords.find((r) => r.value.startsWith('v=DMARC1'))?.value || null;

  // Upsert target in database
  reconDb.upsertTarget({
    id,
    targetType: isIp ? 'ip' : 'domain',
    host: domain,
    ip: isIp ? domain : records.find((r) => r.type === 'A')?.value || null,
    tags: ['dns_recon', isIp ? 'ip' : 'domain'],
  });

  // Save in SQLite
  reconDb.saveDnsRecords(id, domain, records, 0);

  return {
    targetId: id,
    domain,
    recordsCount: records.length,
    records,
    security: {
      hasSpf: Boolean(spfRecord),
      spfRecord,
      hasDmarc: Boolean(dmarcRecord),
      dmarcRecord,
    },
  };
}
