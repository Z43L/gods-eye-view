import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReconControls } from './reconControls.js';

test('ReconControls tab navigation switches views and updates aria attributes', () => {
  // Setup minimal DOM mock
  const tabs = ['scan', 'dossier', 'targets'];
  const tabBtns = tabs.map((t) => {
    const btn = {
      dataset: { tab: t },
      classList: new Set(t === 'scan' ? ['active'] : []),
      setAttribute(k, v) { this[k] = v; },
      addEventListener() {},
      removeEventListener() {},
    };
    btn.classList.toggle = (cls, force) => {
      if (force) btn.classList.add(cls);
      else btn.classList.delete(cls);
    };
    return btn;
  });

  const views = {
    scan: { hidden: false },
    dossier: { hidden: true },
    targets: { hidden: true },
  };

  const originalDocument = globalThis.document;
  globalThis.document = {
    querySelectorAll: (sel) => (sel.includes('.recon-tab-btn') ? tabBtns : []),
    querySelector: () => null,
    getElementById: (id) => {
      if (id === 'recon-view-scan') return views.scan;
      if (id === 'recon-view-dossier') return views.dossier;
      if (id === 'recon-view-targets') return views.targets;
      return null;
    },
  };

  try {
    const mockClient = {
      listTargets: async () => ({ targets: [] }),
    };

    const ctrl = new ReconControls({
      reconClient: mockClient,
    });

    ctrl.switchTab('dossier');
    assert.equal(views.scan.hidden, true);
    assert.equal(views.dossier.hidden, false);
    assert.equal(views.targets.hidden, true);

    ctrl.switchTab('targets');
    assert.equal(views.scan.hidden, true);
    assert.equal(views.dossier.hidden, true);
    assert.equal(views.targets.hidden, false);

    ctrl.destroy();
    assert.equal(ctrl.destroyed, true);
  } finally {
    globalThis.document = originalDocument;
  }
});

test('ReconControls triggers fingerprint, traceroute, and dns recon endpoints', async () => {
  let fpCalled = false;
  let trCalled = false;
  let dnsCalled = false;
  let targetIdQueried = null;

  const mockClient = {
    async runFingerprint({ host, ports, targetType }) {
      fpCalled = true;
      return { ok: true, targetId: `host:${host}`, host, ports, targetType };
    },
    async runTraceroute({ target, maxHops }) {
      trCalled = true;
      return { ok: true, targetId: `host:${target}`, target, maxHops };
    },
    async runDnsRecon({ domain }) {
      dnsCalled = true;
      return { ok: true, targetId: `host:${domain}`, domain };
    },
    async getTargetDossier(id) {
      targetIdQueried = id;
      return {
        ok: true,
        target: { id, host: '1.1.1.1', target_type: 'server', tags: ['dns'] },
        fingerprints: [{ port: 80, protocol: 'http', status_code: 200, server_banner: 'cloudflare' }],
        network_traces: [{ hops: [{ hop: 1, ip: '1.1.1.1', rttMs: 12 }] }],
        dns_records: [{ record_type: 'A', record_value: '1.1.1.1' }],
      };
    },
    async listTargets() {
      return { ok: true, targets: [{ id: 'host:1.1.1.1', host: '1.1.1.1', target_type: 'server' }] };
    },
  };

  const originalDocument = globalThis.document;
  const makeElement = (props) => ({
    addEventListener() {},
    removeEventListener() {},
    querySelectorAll: () => [],
    ...props,
  });

  const elements = {
    targetInput: makeElement({ value: '1.1.1.1', focus() {} }),
    portsInput: makeElement({ value: '80, 443' }),
    targetType: makeElement({ value: 'server' }),
    hopsInput: makeElement({ value: '15' }),
    statusBar: makeElement({ className: '' }),
    statusText: makeElement({ textContent: '' }),
    dossierContent: makeElement({ innerHTML: '' }),
    dossierIdInput: makeElement({ value: '' }),
    targetsList: makeElement({ innerHTML: '' }),
  };

  globalThis.document = {
    querySelectorAll: () => [],
    querySelector: () => null,
    getElementById: (id) => {
      if (id === 'recon-target-input') return elements.targetInput;
      if (id === 'recon-ports-input') return elements.portsInput;
      if (id === 'recon-target-type') return elements.targetType;
      if (id === 'recon-hops-input') return elements.hopsInput;
      if (id === 'recon-scan-status') return elements.statusBar;
      if (id === 'recon-status-text') return elements.statusText;
      if (id === 'recon-dossier-content') return elements.dossierContent;
      if (id === 'recon-dossier-id-input') return elements.dossierIdInput;
      if (id === 'recon-targets-list') return elements.targetsList;
      return null;
    },
  };

  try {
    const ctrl = new ReconControls({
      reconClient: mockClient,
      actions: { showToast() {} },
    });

    await ctrl.runFingerprint();
    assert.equal(fpCalled, true);
    assert.equal(targetIdQueried, 'host:1.1.1.1');

    await ctrl.runTraceroute();
    assert.equal(trCalled, true);

    await ctrl.runDnsRecon();
    assert.equal(dnsCalled, true);

    await ctrl.refreshTargets();
    assert.ok(elements.targetsList.innerHTML.includes('1.1.1.1'));

    ctrl.destroy();
  } finally {
    globalThis.document = originalDocument;
  }
});
