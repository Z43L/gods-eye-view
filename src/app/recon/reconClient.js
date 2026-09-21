/**
 * Frontend client for God's Eye View Active Reconnaissance and Threat Intelligence subsystem.
 * Interacts with /api/recon/* endpoints and the persistent SQLite intelligence store.
 */

export class ReconClient {
  constructor({ baseUrl = '' } = {}) {
    this.baseUrl = baseUrl;
  }

  /** Retrieve full dossier from SQLite for a specific target */
  async getTargetDossier(targetId) {
    const res = await fetch(`${this.baseUrl}/api/recon/target?id=${encodeURIComponent(targetId)}`);
    if (!res.ok) {
      if (res.status === 404) return null;
      throw new Error(`Failed to load target dossier: ${res.statusText}`);
    }
    return res.json();
  }

  /** Run active HTTP/TLS/RTSP fingerprinting */
  async runFingerprint({ host, targetId = null, targetType = 'server', ports = [80, 443, 554, 8080, 8443] }) {
    const res = await fetch(`${this.baseUrl}/api/recon/fingerprint`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host, targetId, targetType, ports }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Fingerprint failed with status ${res.status}`);
    }
    return res.json();
  }

  /** Run active traceroute and latency geo-probe */
  async runTraceroute({ target, targetId = null, maxHops = 20 }) {
    const res = await fetch(`${this.baseUrl}/api/recon/traceroute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, targetId, maxHops }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Traceroute failed with status ${res.status}`);
    }
    return res.json();
  }

  /** Run active DNS enumeration & surface discovery */
  async runDnsRecon({ domain, targetId = null }) {
    const res = await fetch(`${this.baseUrl}/api/recon/dns`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, targetId }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `DNS recon failed with status ${res.status}`);
    }
    return res.json();
  }

  /** List recently scanned targets from SQLite store */
  async listTargets({ limit = 50, tag = null } = {}) {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (tag) params.set('tag', tag);
    const res = await fetch(`${this.baseUrl}/api/recon/targets?${params.toString()}`);
    if (!res.ok) {
      throw new Error(`Failed to list targets: ${res.statusText}`);
    }
    return res.json();
  }
}

export const defaultReconClient = new ReconClient();
