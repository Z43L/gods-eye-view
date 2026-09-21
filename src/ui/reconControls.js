/**
 * Controller for Reconnaissance, Active Fingerprinting, and Network Threat Intelligence UI.
 * Connects frontend panel with server endpoints /api/recon/*.
 */

import { defaultReconClient } from '../app/recon/reconClient.js';

export class ReconControls {
  constructor({
    elements = {},
    reconClient = defaultReconClient,
    actions = {},
  } = {}) {
    this.elements = elements;
    this.client = reconClient;
    this.actions = actions;
    this.destroyed = false;
    this.listeners = [];

    this._bindTabs();
    this._bindScanForm();
    this._bindDossierView();
    this._bindTargetsView();
  }

  listen(element, event, handler) {
    if (!element || typeof element.addEventListener !== 'function') return;
    element.addEventListener(event, handler);
    this.listeners.push(() => element.removeEventListener(event, handler));
  }

  destroy() {
    this.destroyed = true;
    for (const remove of this.listeners) remove();
    this.listeners = [];
  }

  // ── Tab & Header Navigation ───────────────────────────────────────────────
  _bindTabs() {
    const tabBtns = document.querySelectorAll('.recon-tab-btn[data-tab]');
    tabBtns.forEach((btn) => {
      this.listen(btn, 'click', () => {
        const tab = btn.dataset.tab;
        this.switchTab(tab);
      });
    });

    const header = document.querySelector?.('#recon-panel .panel-header');
    if (header) {
      this.listen(header, 'click', (e) => {
        if (!e.target?.closest?.('.panel-collapse-btn')) {
          const panel = document.getElementById?.('recon-panel');
          if (panel?.classList?.contains?.('collapsed')) {
            this.actions.setPanelCollapsed?.('recon-panel', false);
          }
        }
      });
    }
  }

  switchTab(tabName) {
    if (this.destroyed) return;
    const tabBtns = document.querySelectorAll('.recon-tab-btn[data-tab]');
    tabBtns.forEach((btn) => {
      const active = btn.dataset.tab === tabName;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });

    const views = {
      scan: document.getElementById('recon-view-scan'),
      dossier: document.getElementById('recon-view-dossier'),
      targets: document.getElementById('recon-view-targets'),
    };

    for (const [key, el] of Object.entries(views)) {
      if (el) el.hidden = key !== tabName;
    }

    if (tabName === 'targets') {
      this.refreshTargets();
    }
  }

  // ── Status helper ─────────────────────────────────────────────────────────
  _setStatus(text, state = 'normal') {
    const statusBar = document.getElementById('recon-scan-status');
    const statusText = document.getElementById('recon-status-text');
    if (!statusBar || !statusText) return;

    statusBar.className = `recon-status-bar ${state}`;
    statusText.textContent = text;
  }

  // ── SCAN FORM BINDINGS ───────────────────────────────────────────────────
  _bindScanForm() {
    const hopsSlider = document.getElementById('recon-hops-input');
    const hopsVal = document.getElementById('recon-hops-val');
    if (hopsSlider && hopsVal) {
      this.listen(hopsSlider, 'input', () => {
        hopsVal.textContent = hopsSlider.value;
      });
    }

    // Port presets
    const portPresets = document.querySelectorAll('.recon-chip-btn[data-ports]');
    const portsInput = document.getElementById('recon-ports-input');
    portPresets.forEach((chip) => {
      this.listen(chip, 'click', () => {
        if (portsInput) portsInput.value = chip.dataset.ports;
      });
    });

    // Action buttons
    const fullBtn = document.getElementById('recon-run-full-btn');
    const fpBtn = document.getElementById('recon-run-fingerprint-btn');
    const trBtn = document.getElementById('recon-run-traceroute-btn');
    const dnsBtn = document.getElementById('recon-run-dns-btn');

    this.listen(fullBtn, 'click', () => this.runFullRecon());
    this.listen(fpBtn, 'click', () => this.runFingerprint());
    this.listen(trBtn, 'click', () => this.runTraceroute());
    this.listen(dnsBtn, 'click', () => this.runDnsRecon());
  }

  _getTargetInput() {
    const input = document.getElementById('recon-target-input');
    const val = (input?.value || '').trim();
    if (!val) {
      this._setStatus('Error: Target host or domain is required', 'error');
      input?.focus();
      return null;
    }
    return val;
  }

  _getPortsInput() {
    const input = document.getElementById('recon-ports-input');
    const raw = (input?.value || '80, 443, 554, 8080, 8443').trim();
    return raw
      .split(',')
      .map((p) => parseInt(p.trim(), 10))
      .filter((p) => !isNaN(p) && p > 0 && p <= 65535);
  }

  _getTargetType() {
    const select = document.getElementById('recon-target-type');
    return select?.value || 'server';
  }

  _getMaxHops() {
    const input = document.getElementById('recon-hops-input');
    return parseInt(input?.value || '20', 10);
  }

  // 1. POST /api/recon/fingerprint
  async runFingerprint() {
    const host = this._getTargetInput();
    if (!host) return;
    const targetType = this._getTargetType();
    const ports = this._getPortsInput();

    try {
      this._setStatus(`Fingerprinting ${host} on ${ports.length} ports...`, 'busy');
      const result = await this.client.runFingerprint({ host, targetType, ports });
      this._setStatus(`Fingerprint complete for ${host}`, 'success');
      this.actions.showToast?.(`Fingerprint completed for ${host}`);
      if (result.targetId) {
        this.loadDossier(result.targetId);
      }
    } catch (err) {
      this._setStatus(`Fingerprint failed: ${err.message}`, 'error');
    }
  }

  // 2. POST /api/recon/traceroute
  async runTraceroute() {
    const target = this._getTargetInput();
    if (!target) return;
    const maxHops = this._getMaxHops();

    try {
      this._setStatus(`Executing traceroute to ${target} (max ${maxHops} hops)...`, 'busy');
      const result = await this.client.runTraceroute({ target, maxHops });
      this._setStatus(`Traceroute complete (${result.totalHops || result.hops?.length || 0} hops)`, 'success');
      this.actions.showToast?.(`Traceroute completed for ${target}`);
      if (result.targetId) {
        this.loadDossier(result.targetId);
      }
    } catch (err) {
      this._setStatus(`Traceroute failed: ${err.message}`, 'error');
    }
  }

  // 3. POST /api/recon/dns
  async runDnsRecon() {
    const domain = this._getTargetInput();
    if (!domain) return;

    try {
      this._setStatus(`Running DNS reconnaissance for ${domain}...`, 'busy');
      const result = await this.client.runDnsRecon({ domain });
      this._setStatus(`DNS Recon complete for ${domain}`, 'success');
      this.actions.showToast?.(`DNS Recon complete for ${domain}`);
      if (result.targetId) {
        this.loadDossier(result.targetId);
      }
    } catch (err) {
      this._setStatus(`DNS Recon failed: ${err.message}`, 'error');
    }
  }

  // Combined Full Recon
  async runFullRecon() {
    const host = this._getTargetInput();
    if (!host) return;
    const targetType = this._getTargetType();
    const ports = this._getPortsInput();
    const maxHops = this._getMaxHops();

    try {
      this._setStatus(`[1/3] Running DNS reconnaissance for ${host}...`, 'busy');
      await this.client.runDnsRecon({ domain: host }).catch(() => null);

      this._setStatus(`[2/3] Fingerprinting ${host}...`, 'busy');
      const fpResult = await this.client.runFingerprint({ host, targetType, ports }).catch(() => null);

      this._setStatus(`[3/3] Tracing network path to ${host}...`, 'busy');
      const trResult = await this.client.runTraceroute({ target: host, maxHops }).catch(() => null);

      this._setStatus(`Full reconnaissance complete for ${host}`, 'success');
      this.actions.showToast?.(`Full intelligence scan complete for ${host}`);

      const targetId = fpResult?.targetId || trResult?.targetId || `host:${host}`;
      this.switchTab('dossier');
      this.loadDossier(targetId);
    } catch (err) {
      this._setStatus(`Recon failed: ${err.message}`, 'error');
    }
  }

  // ── DOSSIER VIEW (GET /api/recon/target?id=...) ───────────────────────────
  _bindDossierView() {
    const fetchBtn = document.getElementById('recon-dossier-fetch-btn');
    const idInput = document.getElementById('recon-dossier-id-input');

    this.listen(fetchBtn, 'click', () => {
      const id = idInput?.value?.trim();
      if (id) this.loadDossier(id);
    });

    this.listen(idInput, 'keydown', (e) => {
      if (e.key === 'Enter') {
        const id = idInput?.value?.trim();
        if (id) this.loadDossier(id);
      }
    });
  }

  async loadDossier(targetId) {
    const container = document.getElementById('recon-dossier-content');
    const idInput = document.getElementById('recon-dossier-id-input');
    if (idInput) idInput.value = targetId;

    if (!container) return;
    container.innerHTML = `<div class="recon-empty-state">Loading dossier for ${this._escape(targetId)}...</div>`;

    try {
      const data = await this.client.getTargetDossier(targetId);
      if (!data || !data.target) {
        container.innerHTML = `<div class="recon-empty-state">Target not found: ${this._escape(targetId)}</div>`;
        return;
      }
      this.renderDossier(data, container);
    } catch (err) {
      container.innerHTML = `<div class="recon-empty-state" style="color: #ff4444;">Failed to load dossier: ${this._escape(err.message)}</div>`;
    }
  }

  renderDossier(data, container) {
    const { target, fingerprints = [], network_traces = [], dns_records = [] } = data;
    const tags = target.tags || [];

    let html = `
      <!-- Target Summary Card -->
      <div class="recon-card">
        <div class="recon-card-header">
          <span class="recon-card-title">${this._escape(target.host)}</span>
          <span class="recon-badge accent">${this._escape(target.target_type || 'TARGET')}</span>
        </div>
        <div class="recon-meta-grid">
          <span class="recon-meta-key">ID</span>
          <span class="recon-meta-val">${this._escape(target.id)}</span>
          <span class="recon-meta-key">IP</span>
          <span class="recon-meta-val">${this._escape(target.ip || '—')}</span>
          <span class="recon-meta-key">Last Seen</span>
          <span class="recon-meta-val">${target.last_scanned ? new Date(target.last_scanned).toLocaleString() : '—'}</span>
        </div>
        ${
          tags.length > 0
            ? `<div class="recon-target-item-tags">
                ${tags.map((t) => `<span class="recon-badge">${this._escape(t)}</span>`).join('')}
              </div>`
            : ''
        }
      </div>
    `;

    // Fingerprints & Ports Card
    if (fingerprints.length > 0) {
      html += `
        <div class="recon-card">
          <div class="recon-card-header">
            <span class="recon-card-title">OPEN PORTS & SERVICES (${fingerprints.length})</span>
          </div>
          <div class="recon-table-wrap">
            <table class="recon-table">
              <thead>
                <tr><th>Port</th><th>Proto</th><th>Status</th><th>Banner / Service</th></tr>
              </thead>
              <tbody>
                ${fingerprints
                  .map(
                    (fp) => `
                  <tr>
                    <td><strong style="color:var(--accent);">${fp.port}</strong></td>
                    <td>${this._escape(fp.protocol?.toUpperCase() || 'TCP')}</td>
                    <td><span class="recon-badge ${fp.status_code >= 200 && fp.status_code < 400 ? 'accent' : ''}">${fp.status_code || 'OPEN'}</span></td>
                    <td>${this._escape(fp.server_banner || fp.page_title || '—')}</td>
                  </tr>
                `,
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // DNS Records Card
    if (dns_records.length > 0) {
      html += `
        <div class="recon-card">
          <div class="recon-card-header">
            <span class="recon-card-title">DNS RECORDS (${dns_records.length})</span>
          </div>
          <div class="recon-table-wrap">
            <table class="recon-table">
              <thead>
                <tr><th>Type</th><th>Value</th><th>TTL</th></tr>
              </thead>
              <tbody>
                ${dns_records
                  .map(
                    (rec) => `
                  <tr>
                    <td><span class="recon-badge accent">${this._escape(rec.record_type)}</span></td>
                    <td class="recon-meta-val">${this._escape(rec.record_value)}</td>
                    <td>${rec.ttl || '—'}</td>
                  </tr>
                `,
                  )
                  .join('')}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Network Traceroute Card
    if (network_traces.length > 0) {
      const trace = network_traces[0];
      const hops = trace.hops || [];
      html += `
        <div class="recon-card">
          <div class="recon-card-header">
            <span class="recon-card-title">NETWORK TRACEROUTE (${hops.length} HOPS)</span>
            <span class="recon-badge">${trace.total_rtt_ms ? `${Math.round(trace.total_rtt_ms)}ms` : ''}</span>
          </div>
          <div class="recon-hops-list">
            ${hops
              .map(
                (h) => `
              <div class="recon-hop-row">
                <span class="recon-hop-num">#${h.hop}</span>
                <span class="recon-hop-ip" title="${this._escape(h.hostname || h.ip)}">${this._escape(h.ip)}</span>
                <span class="recon-hop-geo">${this._escape([h.city, h.country].filter(Boolean).join(', ') || h.asn || '—')}</span>
                <span class="recon-hop-rtt" style="color: ${h.rttMs > 150 ? '#ff4444' : h.rttMs > 60 ? '#ffaa00' : '#00ff88'};">
                  ${h.rttMs ? `${Math.round(h.rttMs)}ms` : '*'}
                </span>
                ${
                  h.lat && h.lon
                    ? `<button type="button" class="recon-hop-fly-btn" data-lat="${h.lat}" data-lon="${h.lon}" title="Fly globe to this hop location">FLY</button>`
                    : ''
                }
              </div>
            `,
              )
              .join('')}
          </div>
        </div>
      `;
    }

    container.innerHTML = html;

    // Attach fly-to handlers for hops with geo coordinates
    container.querySelectorAll('.recon-hop-fly-btn').forEach((btn) => {
      this.listen(btn, 'click', () => {
        const lat = parseFloat(btn.dataset.lat);
        const lon = parseFloat(btn.dataset.lon);
        if (!isNaN(lat) && !isNaN(lon)) {
          this.flyToLocation(lat, lon);
        }
      });
    });
  }

  flyToLocation(latitude, longitude) {
    if (this.actions.flyToCoordinates) {
      this.actions.flyToCoordinates({ latitude, longitude, height: 25000 });
    } else if (window.__gevViewer) {
      try {
        const Cesium = window.Cesium;
        if (Cesium) {
          window.__gevViewer.camera.flyTo({
            destination: Cesium.Cartesian3.fromDegrees(longitude, latitude, 25000),
            duration: 1.8,
          });
        }
      } catch (err) {
        console.warn('Globe fly-to failed:', err);
      }
    }
  }

  // ── TARGETS VIEW (GET /api/recon/targets?limit=50&tag=...) ─────────────────
  _bindTargetsView() {
    const refreshBtn = document.getElementById('recon-refresh-targets-btn');
    const tagInput = document.getElementById('recon-tag-filter');
    const limitSelect = document.getElementById('recon-limit-select');

    this.listen(refreshBtn, 'click', () => this.refreshTargets());
    this.listen(limitSelect, 'change', () => this.refreshTargets());
    this.listen(tagInput, 'keydown', (e) => {
      if (e.key === 'Enter') this.refreshTargets();
    });
  }

  async refreshTargets() {
    const listContainer = document.getElementById('recon-targets-list');
    const tagInput = document.getElementById('recon-tag-filter');
    const limitSelect = document.getElementById('recon-limit-select');

    if (!listContainer) return;
    listContainer.innerHTML = `<div class="recon-empty-state">Refreshing target cache...</div>`;

    const tag = tagInput?.value?.trim() || null;
    const limit = parseInt(limitSelect?.value || '50', 10);

    try {
      const res = await this.client.listTargets({ limit, tag });
      const targets = res.targets || [];

      if (!targets.length) {
        listContainer.innerHTML = `<div class="recon-empty-state">No targets found. Run a scan to discover intelligence.</div>`;
        return;
      }

      listContainer.innerHTML = targets
        .map(
          (t) => `
        <div class="recon-target-item" data-target-id="${this._escape(t.id)}">
          <div class="recon-target-item-top">
            <span class="recon-target-host">${this._escape(t.host)}</span>
            <span class="recon-badge ${t.target_type === 'camera' ? 'warn' : 'accent'}">${this._escape(t.target_type || 'TARGET')}</span>
          </div>
          <div class="recon-target-date">Last scan: ${t.last_scanned ? new Date(t.last_scanned).toLocaleString() : '—'}</div>
          ${
            t.tags && t.tags.length > 0
              ? `<div class="recon-target-item-tags">
                  ${t.tags.map((tag) => `<span class="recon-badge">${this._escape(tag)}</span>`).join('')}
                </div>`
              : ''
          }
        </div>
      `,
        )
        .join('');

      listContainer.querySelectorAll('.recon-target-item').forEach((item) => {
        this.listen(item, 'click', () => {
          const targetId = item.dataset.targetId;
          if (targetId) {
            this.switchTab('dossier');
            this.loadDossier(targetId);
          }
        });
      });
    } catch (err) {
      listContainer.innerHTML = `<div class="recon-empty-state" style="color: #ff4444;">Failed to load targets: ${this._escape(err.message)}</div>`;
    }
  }

  _escape(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
}
