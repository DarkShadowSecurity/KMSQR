// Copyright (c) 2026 DarkShadowSec LLC.
// Licensed under the MIT License. See LICENSE for terms. Provided "as is", without warranty.
const API = '/api/v1';
let TOKEN = sessionStorage.getItem('pqkms_token') || '';
let selectedKey = null;
let keysCache = [];

// ---- api helpers ----
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    ...opts,
    headers: {
      'Authorization': 'Bearer ' + TOKEN,
      'Content-Type': 'application/json',
      ...(opts.headers || {})
    }
  });
  const text = await res.text();
  let body = text;
  try { body = JSON.parse(text); } catch {}
  if (!res.ok) throw new Error(typeof body === 'object' ? (body.detail || JSON.stringify(body)) : text);
  return body;
}

function toast(msg, isErr = false) {
  const t = document.createElement('div');
  t.className = 'toast' + (isErr ? ' err' : '');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4200);
}

function b64(s) {
  // utf-8 → base64
  return btoa(unescape(encodeURIComponent(s)));
}
function fromB64(s) {
  try { return decodeURIComponent(escape(atob(s))); }
  catch { return '[binary: ' + s.length + ' b64 chars]'; }
}

// ---- auth gate ----
async function tryAuth() {
  try {
    await api('/status');
    document.getElementById('gate').classList.add('hidden');
    document.getElementById('app-header').classList.remove('hidden');
    document.getElementById('app-main').classList.remove('hidden');
    const s = await api('/status');
    if (!s.pq_available) {
      const pill = document.getElementById('pq-pill');
      pill.replaceChildren();
      const dot = document.createElement('span');
      dot.className = 'dot';
      dot.style.color = 'var(--warn)';
      pill.appendChild(dot);
      pill.appendChild(document.createTextNode(' PQ: fallback (classical only)'));
      pill.style.borderColor = 'var(--warn)';
      pill.style.color = 'var(--warn)';
    }
    refreshAll();
  } catch (e) {
    const err = document.getElementById('gate-err');
    err.textContent = e.message;
    err.classList.remove('hidden');
  }
}

document.getElementById('gate-btn').onclick = () => {
  TOKEN = document.getElementById('gate-token').value.trim();
  sessionStorage.setItem('pqkms_token', TOKEN);
  tryAuth();
};
document.getElementById('gate-token').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('gate-btn').click();
});
document.getElementById('logout-btn').onclick = () => {
  sessionStorage.removeItem('pqkms_token');
  location.reload();
};

// ---- keys ----
function makeKeyRow(k) {
  // Build the row with DOM APIs only — k.name and k.description are operator-supplied
  // and must never be interpolated into innerHTML.
  const tr = document.createElement('tr');

  const nameTd = document.createElement('td');
  const strong = document.createElement('strong');
  strong.textContent = k.name;
  nameTd.appendChild(strong);

  const typeTd = document.createElement('td');
  const badge = document.createElement('span');
  badge.className = 'kbadge ' + k.key_type;
  badge.textContent = k.key_type;
  typeTd.appendChild(badge);

  const verTd = document.createElement('td');
  verTd.className = 'mono';
  verTd.textContent = 'v' + k.current_version;

  const idTd = document.createElement('td');
  idTd.className = 'mono';
  idTd.textContent = k.id.slice(0, 8) + '…';

  const btnTd = document.createElement('td');
  const btn = document.createElement('button');
  btn.className = 'ghost small';
  btn.textContent = 'select';
  btn.onclick = () => selectKey(k);
  btnTd.appendChild(btn);

  tr.appendChild(nameTd);
  tr.appendChild(typeTd);
  tr.appendChild(verTd);
  tr.appendChild(idTd);
  tr.appendChild(btnTd);
  return tr;
}

async function refreshKeys() {
  const keys = await api('/keys');
  keysCache = keys;
  document.getElementById('keys-count').textContent = keys.length;
  const tbody = document.querySelector('#keys-table tbody');
  tbody.replaceChildren();
  for (const k of keys) {
    tbody.appendChild(makeKeyRow(k));
  }
}

function selectKey(k) {
  selectedKey = k;
  document.getElementById('sel-key-display').classList.remove('hidden');
  document.getElementById('sel-key-empty').classList.add('hidden');
  document.getElementById('ops').classList.remove('hidden');
  document.getElementById('sel-key-name').textContent = k.name;
  document.getElementById('sel-key-id').textContent = '· ' + k.id;
  const badge = document.getElementById('sel-key-type');
  badge.textContent = k.key_type;
  badge.className = 'kbadge ' + k.key_type;

  // enable appropriate buttons
  const t = k.key_type;
  document.getElementById('op-encrypt').disabled = t !== 'aead';
  document.getElementById('op-decrypt').disabled = t !== 'aead';
  document.getElementById('op-sign').disabled = t !== 'sig';
  document.getElementById('op-verify').disabled = t !== 'sig';
  document.getElementById('op-wrap').disabled = t !== 'kem';
  document.getElementById('op-unwrap').disabled = t !== 'kem';
}

document.getElementById('new-key-btn').onclick = async () => {
  const name = document.getElementById('new-key-name').value.trim();
  const key_type = document.getElementById('new-key-type').value;
  const description = document.getElementById('new-key-desc').value.trim() || null;
  if (!name) return toast('name required', true);
  try {
    const k = await api('/keys', { method: 'POST', body: JSON.stringify({ name, key_type, description }) });
    toast('created ' + k.key_type + ' key ' + k.name);
    document.getElementById('new-key-name').value = '';
    document.getElementById('new-key-desc').value = '';
    await refreshAll();
  } catch (e) { toast(e.message, true); }
};

// ---- ops ----
async function doOp(fn) {
  if (!selectedKey) return;
  const out = document.getElementById('op-out');
  out.classList.remove('err');
  try {
    const r = await fn();
    out.textContent = JSON.stringify(r, null, 2);
    await refreshAudit();
  } catch (e) {
    out.classList.add('err');
    out.textContent = e.message;
  }
}

document.getElementById('op-encrypt').onclick = () => doOp(async () => {
  const pt = document.getElementById('op-input').value;
  return api('/keys/' + selectedKey.id + '/encrypt', {
    method: 'POST', body: JSON.stringify({ plaintext_b64: b64(pt) })
  });
});
document.getElementById('op-decrypt').onclick = () => doOp(async () => {
  const ct = document.getElementById('op-ct').value.trim();
  const r = await api('/keys/' + selectedKey.id + '/decrypt', {
    method: 'POST', body: JSON.stringify({ ciphertext_b64: ct })
  });
  return { ...r, plaintext_utf8: fromB64(r.plaintext_b64) };
});
document.getElementById('op-sign').onclick = () => doOp(async () => {
  const m = document.getElementById('op-input').value;
  return api('/keys/' + selectedKey.id + '/sign', {
    method: 'POST', body: JSON.stringify({ message_b64: b64(m) })
  });
});
document.getElementById('op-verify').onclick = () => doOp(async () => {
  const m = document.getElementById('op-input').value;
  const sig = document.getElementById('op-ct').value.trim();
  return api('/keys/' + selectedKey.id + '/verify', {
    method: 'POST', body: JSON.stringify({ message_b64: b64(m), signature_b64: sig })
  });
});
document.getElementById('op-wrap').onclick = () => doOp(async () => {
  const dk = document.getElementById('op-input').value;
  // treat input as either base64 already or utf-8 to encode
  const dkB64 = /^[A-Za-z0-9+/=]+$/.test(dk) && dk.length % 4 === 0 ? dk : b64(dk);
  return api('/keys/' + selectedKey.id + '/wrap', {
    method: 'POST', body: JSON.stringify({ data_key_b64: dkB64 })
  });
});
document.getElementById('op-unwrap').onclick = () => doOp(async () => {
  const encap = document.getElementById('op-encap').value.trim();
  const wrapped = document.getElementById('op-ct').value.trim();
  return api('/keys/' + selectedKey.id + '/unwrap', {
    method: 'POST', body: JSON.stringify({ encapsulation_b64: encap, wrapped_key_b64: wrapped })
  });
});
document.getElementById('op-rotate').onclick = () => doOp(async () => {
  const r = await api('/keys/' + selectedKey.id + '/rotate', { method: 'POST' });
  selectedKey = r;
  await refreshKeys();
  selectKey(r);
  toast('rotated ' + r.name + ' → v' + r.current_version);
  return r;
});

// ---- tokens ----
document.getElementById('new-tok-btn').onclick = async () => {
  const name = document.getElementById('new-tok-name').value.trim();
  const scopes = [...document.querySelectorAll('#new-tok-name ~ * input[type=checkbox]:checked')].map(c => c.value);
  if (!name || scopes.length === 0) return toast('name and at least one scope required', true);
  try {
    const r = await api('/tokens', { method: 'POST', body: JSON.stringify({ name, scopes }) });
    const out = document.getElementById('tok-out');
    out.classList.remove('hidden');
    out.textContent = 'TOKEN (copy now, shown only once):\n\n' + r.token;
    document.getElementById('new-tok-name').value = '';
    await refreshAudit();
  } catch (e) { toast(e.message, true); }
};

// ---- audit ----
function makeAuditEntry(e) {
  const div = document.createElement('div');
  div.className = 'audit-entry';

  const seqDiv = document.createElement('div');
  seqDiv.className = 'seq';
  seqDiv.textContent = '#' + e.seq;

  const midDiv = document.createElement('div');
  const actionDiv = document.createElement('div');
  actionDiv.className = 'action';
  actionDiv.textContent = e.action + ' ';
  if (e.target) {
    const targetSpan = document.createElement('span');
    targetSpan.style.color = 'var(--ink-2)';
    targetSpan.textContent = '· ' + e.target.slice(0, 8) + '…';
    actionDiv.appendChild(targetSpan);
  }
  midDiv.appendChild(actionDiv);
  if (e.detail && e.detail !== '{}') {
    const detailDiv = document.createElement('div');
    detailDiv.className = 'detail';
    detailDiv.textContent = e.detail;
    midDiv.appendChild(detailDiv);
  }

  const tsDiv = document.createElement('div');
  tsDiv.className = 'ts';
  tsDiv.textContent = new Date(e.ts).toLocaleString();

  div.appendChild(seqDiv);
  div.appendChild(midDiv);
  div.appendChild(tsDiv);
  return div;
}

async function refreshAudit() {
  try {
    const r = await api('/audit?limit=100');
    const list = document.getElementById('audit-list');
    list.replaceChildren();
    for (const e of r.entries) {
      list.appendChild(makeAuditEntry(e));
    }
  } catch {}
}

document.getElementById('verify-chain-btn').onclick = async () => {
  try {
    const r = await api('/audit/verify');
    if (r.valid) toast('audit chain valid · all signatures verified');
    else toast('CHAIN INVALID at seq ' + r.first_bad_seq, true);
  } catch (e) { toast(e.message, true); }
};

async function refreshAll() {
  await Promise.all([refreshKeys(), refreshAudit()]);
}

// boot
if (TOKEN) tryAuth();
