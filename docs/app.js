// app.js — glue between the WASM module and the DOM
// Requires chorgly_frontend.js (wasm-bindgen output) in the same directory.
//
// Auth uses P-256 ECDSA keys (Web Crypto API).
// The private key is stored in localStorage as base64-encoded PKCS#8.
// The public key is registered with the server via the init_token challenge flow.

import init, {
  AppState,
  decode_server_msg,
  encode_request_challenge,
  encode_confirm_key,
  encode_signed_payload,
  encode_signed_msg,
  encode_rekey_msg,
} from './pkg/chorgly_frontend.js';

// WebSocket is served at /ws on the same host:port as the HTTP app.
const WS_URL = window.location.protocol === 'https:'
  ? `wss://${window.location.host}/ws`
  : `ws://${window.location.host}/ws`;

// localStorage keys
const KEY_PRIVKEY   = 'chorgly_privkey';   // base64 PKCS#8 private key
const KEY_PUBKEY    = 'chorgly_pubkey';    // base64 SPKI public key
const KEY_KEY_ID    = 'chorgly_key_id';   // hex fingerprint of the public key
const KEY_KEY_ADDED = 'chorgly_key_added'; // ISO timestamp when key was registered

// Key validity: 7 days.  Re-key trigger: 1/4 into the validity period (42 hours).
const KEY_VALIDITY_MS  = 7 * 24 * 3600 * 1000;
const REKEY_TRIGGER_MS = KEY_VALIDITY_MS / 4;

let ws = null;
let state = null; // AppState (WASM)

// Pending challenge state (between RequestChallenge → ConfirmKey).
let pendingPubkeySpki = null;  // Uint8Array

// ---- bootstrap ----

async function main() {
  await init();
  state = new AppState();

  // Read init_token from URL query string (first-time registration link from admin).
  const params = new URLSearchParams(window.location.search);
  const initToken = params.get('token');
  if (initToken) {
    // Redirect to clean URL immediately to avoid leaking the token in history.
    const clean = window.location.pathname + window.location.hash;
    window.history.replaceState({}, '', clean);
    // Start key registration flow.
    showApp(); // optimistic
    await registerNewKey(initToken);
    return;
  }

  // Returning user: check for stored key.
  const privkeyB64 = localStorage.getItem(KEY_PRIVKEY);
  if (privkeyB64) {
    showApp();
    connect();
  } else {
    showAuth();
  }
}

// ---- EC key helpers ----

async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,  // extractable so we can export and store
    ['sign', 'verify'],
  );
}

async function exportPrivkey(key) {
  const buf = await crypto.subtle.exportKey('pkcs8', key);
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function exportPubkey(key) {
  const buf = await crypto.subtle.exportKey('spki', key);
  return new Uint8Array(buf);
}

async function importPrivkey(b64) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey('pkcs8', buf, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function signData(privkey, data) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privkey, data);
  return new Uint8Array(sig);
}

async function keyFingerprint(spkiBytes) {
  const hash = await crypto.subtle.digest('SHA-256', spkiBytes);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---- screen helpers ----

function showAuth() {
  document.getElementById('auth-screen').hidden = false;
  document.getElementById('app-screen').hidden = true;
}

function showApp() {
  document.getElementById('auth-screen').hidden = true;
  document.getElementById('app-screen').hidden = false;
}

// ---- key registration (init_token flow) ----

async function registerNewKey(initToken) {
  const kp = await generateKeyPair();
  const spkiBytes = await exportPubkey(kp.publicKey);
  const privB64 = await exportPrivkey(kp.privateKey);
  const keyId = await keyFingerprint(spkiBytes);

  // Store key material first (before connecting) so a restart can retry.
  localStorage.setItem(KEY_PRIVKEY, privB64);
  localStorage.setItem(KEY_PUBKEY, btoa(String.fromCharCode(...spkiBytes)));
  localStorage.setItem(KEY_KEY_ID, keyId);
  localStorage.setItem(KEY_KEY_ADDED, new Date().toISOString());

  pendingPubkeySpki = spkiBytes;
  connectForRegistration(initToken, kp.privateKey, spkiBytes);
}

function connectForRegistration(initToken, privkey, spkiBytes) {
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';

  ws.addEventListener('open', () => {
    // Step 1: send RequestChallenge with our public key + init_token.
    const bytes = encode_request_challenge(initToken, spkiBytes);
    ws.send(bytes);
  });

  ws.addEventListener('message', async (ev) => {
    const bytes = new Uint8Array(ev.data);
    let msg;
    try { msg = decode_server_msg(bytes); } catch (e) {
      console.error('decode error', e);
      return;
    }

    if ('Challenge' in msg) {
      // Step 3: sign (challenge || spki) and send ConfirmKey.
      const challenge = new Uint8Array(msg.Challenge.token);
      const signedData = new Uint8Array(challenge.length + spkiBytes.length);
      signedData.set(challenge, 0);
      signedData.set(spkiBytes, challenge.length);

      const sig = await signData(privkey, signedData);
      const cfm = encode_confirm_key(sig);
      ws.send(cfm);
      return;
    }

    if ('AuthOk' in msg) {
      document.getElementById('user-name').textContent = msg.AuthOk.user.name;
      // Switch to normal authenticated session.
      ws.close();
      connect();
      return;
    }

    if ('AuthFail' in msg) {
      // Registration failed; clear stored keys so user can try again.
      clearStoredKey();
      document.getElementById('auth-error').textContent =
        msg.AuthFail?.reason ?? 'Registration failed.';
      document.getElementById('auth-error').hidden = false;
      showAuth();
      ws.close();
      return;
    }
  });

  ws.addEventListener('close', () => {});
  ws.addEventListener('error', e => console.error('WS error', e));
}

function clearStoredKey() {
  localStorage.removeItem(KEY_PRIVKEY);
  localStorage.removeItem(KEY_PUBKEY);
  localStorage.removeItem(KEY_KEY_ID);
  localStorage.removeItem(KEY_KEY_ADDED);
}

// ---- normal authenticated connection ----

function connect() {
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';

  ws.addEventListener('open', async () => {
    // Check whether it's time to re-key (at 1/4 of validity period elapsed).
    const addedAt = localStorage.getItem(KEY_KEY_ADDED);
    if (addedAt) {
      const elapsed = Date.now() - new Date(addedAt).getTime();
      if (elapsed >= REKEY_TRIGGER_MS) {
        await initiateReKey();
        return;
      }
    }
    // Normal session: send ListAll to get initial data.
    await sendSigned('"ListAll"');
  });

  ws.addEventListener('message', async (ev) => {
    const bytes = new Uint8Array(ev.data);
    let msg;
    try { msg = decode_server_msg(bytes); } catch (e) {
      console.error('failed to decode server message', e);
      return;
    }
    await handleServerMsg(msg);
  });

  ws.addEventListener('close', () => {
    setTimeout(() => {
      if (localStorage.getItem(KEY_PRIVKEY)) connect();
    }, 3000);
  });

  ws.addEventListener('error', e => console.error('WebSocket error', e));
}

async function loadPrivkey() {
  const b64 = localStorage.getItem(KEY_PRIVKEY);
  if (!b64) return null;
  try { return await importPrivkey(b64); } catch { return null; }
}

// ---- sending signed messages ----

async function sendSigned(payloadJson) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const privkey = await loadPrivkey();
  if (!privkey) { showAuth(); return; }

  const keyId = localStorage.getItem(KEY_KEY_ID);
  const payload = encode_signed_payload(payloadJson);
  const sig = await signData(privkey, payload);
  const msg = encode_signed_msg(keyId, payload, sig);
  ws.send(msg);
}

// ---- re-keying ----

async function initiateReKey() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  const oldPrivkey = await loadPrivkey();
  if (!oldPrivkey) { showAuth(); return; }
  const oldKeyId = localStorage.getItem(KEY_KEY_ID);

  // Generate new key pair.
  const newKp = await generateKeyPair();
  const newSpki = await exportPubkey(newKp.publicKey);
  const newPrivB64 = await exportPrivkey(newKp.privateKey);
  const newKeyId = await keyFingerprint(newSpki);

  // Build the ReKey payload.
  const payloadJson = JSON.stringify({ ReKey: { new_pubkey_spki: Array.from(newSpki) } });
  const payload = encode_signed_payload(payloadJson);

  // Both old and new keys sign the same payload bytes.
  const oldSig = await signData(oldPrivkey, payload);
  const newSig = await signData(newKp.privateKey, payload);

  const msg = encode_rekey_msg(oldKeyId, payload, oldSig, newSig);
  ws.send(msg);

  // Store new key material (will be active after server accepts ReKey).
  localStorage.setItem(KEY_PRIVKEY, newPrivB64);
  localStorage.setItem(KEY_PUBKEY, btoa(String.fromCharCode(...newSpki)));
  localStorage.setItem(KEY_KEY_ID, newKeyId);
  localStorage.setItem(KEY_KEY_ADDED, new Date().toISOString());
}

// ---- server message handler ----

async function handleServerMsg(msg) {
  const event = state.apply(msg);

  if (event === 'auth_ok') {
    document.getElementById('user-name').textContent = msg.AuthOk.user.name;
    showApp();
    await sendSigned('"ListAll"');
    return;
  }

  if (event === 'auth_fail') {
    clearStoredKey();
    document.getElementById('auth-error').textContent =
      msg.AuthFail?.reason ?? 'Login failed.';
    document.getElementById('auth-error').hidden = false;
    showAuth();
    return;
  }

  if (event === 'error') {
    console.warn('server error:', msg.Error?.reason);
    return;
  }

  // snapshot / chore_changed / chore_deleted / event_* → re-render
  renderChores();
  renderEvents();
}

// ---- chore rendering ----

function renderChores() {
  const list = document.getElementById('chore-list');
  const empty = document.getElementById('no-chores');

  let chores;
  try {
    chores = state.pending_chores_json();
  } catch (e) {
    console.error('pending_chores_json failed', e);
    return;
  }

  list.innerHTML = '';

  if (!chores || chores.length === 0) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  const now = Date.now();

  for (const c of chores) {
    const li = document.createElement('li');
    li.className = 'chore-item';

    const blocked = state.is_chore_blocked(c.id);
    if (blocked) li.classList.add('blocked');

    const dueMs = c.next_due ? new Date(c.next_due).getTime() : null;
    if (dueMs && dueMs < now) li.classList.add('overdue');

    const title = document.createElement('span');
    title.className = 'chore-title';
    title.textContent = c.title;

    const meta = document.createElement('span');
    meta.className = 'chore-meta';
    if (c.assignee) meta.textContent = `→ ${c.assignee}`;

    const due = document.createElement('span');
    due.className = 'chore-due';
    due.textContent = dueMs ? formatDue(dueMs, now) : '';

    const btn = document.createElement('button');
    btn.className = 'chore-done-btn';
    btn.textContent = 'Done';
    btn.disabled = blocked;
    btn.addEventListener('click', async () => {
      await sendSigned(JSON.stringify({ CompleteChore: { chore_id: c.id } }));
    });

    li.append(title, meta, due, btn);
    list.append(li);
  }
}

function formatDue(dueMs, nowMs) {
  const diff = dueMs - nowMs;
  const abs = Math.abs(diff);
  const mins  = Math.floor(abs / 60000);
  const hours = Math.floor(abs / 3600000);
  const days  = Math.floor(abs / 86400000);

  const label = days > 0 ? `${days}d` : hours > 0 ? `${hours}h` : `${mins}m`;
  return diff < 0 ? `overdue ${label}` : `due in ${label}`;
}

// ---- event rendering ----

function renderEvents() {
  const section = document.getElementById('events-section');
  const list = document.getElementById('event-list');

  let events;
  try {
    events = state.pending_events_json();
  } catch (e) {
    console.error('pending_events_json failed', e);
    return;
  }

  list.innerHTML = '';

  if (!events || events.length === 0) {
    section.hidden = true;
    return;
  }
  section.hidden = false;

  for (const ev of events) {
    const li = document.createElement('li');
    li.className = 'event-item';

    const name = document.createElement('span');
    name.className = 'event-name';
    name.textContent = ev.name;

    const desc = document.createElement('span');
    desc.className = 'event-desc';
    desc.textContent = ev.description || '';

    const btn = document.createElement('button');
    btn.className = 'event-trigger-btn';
    btn.textContent = 'Happened';
    btn.addEventListener('click', async () => {
      await sendSigned(JSON.stringify({ TriggerEvent: { event_id: ev.id } }));
    });

    li.append(name, desc, btn);
    list.append(li);
  }
}

// ---- add-chore buttons ----

const choreDialog = document.getElementById('add-chore-dialog');
let addingPersonal = false;

document.getElementById('btn-add-common').addEventListener('click', () => {
  addingPersonal = false;
  document.getElementById('add-chore-title').textContent = 'Add common chore';
  choreDialog.showModal();
});

document.getElementById('btn-add-personal').addEventListener('click', () => {
  addingPersonal = true;
  document.getElementById('add-chore-title').textContent = 'Add my chore';
  choreDialog.showModal();
});

document.getElementById('btn-cancel-dialog').addEventListener('click', () => {
  choreDialog.close();
});

document.getElementById('chore-kind').addEventListener('change', (e) => {
  document.getElementById('field-delay').hidden    = e.target.value !== 'RecurringAfterCompletion';
  document.getElementById('field-schedule').hidden = e.target.value !== 'RecurringScheduled';
  document.getElementById('field-deadline').hidden = e.target.value !== 'WithDeadline';
});

document.getElementById('add-chore-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const title = document.getElementById('chore-name').value.trim();
  const kindKey = document.getElementById('chore-kind').value;

  let kind;
  if (kindKey === 'OneTime') {
    kind = 'OneTime';
  } else if (kindKey === 'RecurringAfterCompletion') {
    const hours = parseInt(document.getElementById('chore-delay').value, 10) || 168;
    kind = { RecurringAfterCompletion: { delay_secs: hours * 3600 } };
  } else if (kindKey === 'RecurringScheduled') {
    const schedule = document.getElementById('chore-schedule').value.trim();
    kind = { RecurringScheduled: { schedule } };
  } else {
    const deadline = document.getElementById('chore-deadline').value;
    kind = { WithDeadline: { deadline } };
  }

  let visible_to = null;
  let assignee = null;
  let can_complete = null;

  if (addingPersonal) {
    const uid = state.current_user_id();
    visible_to = [uid];
    assignee = uid;
    can_complete = [uid];
  }

  await sendSigned(JSON.stringify({
    AddChore: { title, kind, visible_to, assignee, can_complete, depends_on: [], depends_on_events: [] },
  }));
  choreDialog.close();
});

// ---- add-event button ----

const eventDialog = document.getElementById('add-event-dialog');

document.getElementById('btn-add-event').addEventListener('click', () => {
  eventDialog.showModal();
});

document.getElementById('btn-cancel-event-dialog').addEventListener('click', () => {
  eventDialog.close();
});

document.getElementById('add-event-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('event-name').value.trim();
  const description = document.getElementById('event-description').value.trim();
  await sendSigned(JSON.stringify({ AddEvent: { name, description } }));
  eventDialog.close();
});

// ---- auth form (fallback: not normally used with EC auth) ----
document.getElementById('auth-form').addEventListener('submit', (e) => {
  e.preventDefault();
  // With EC auth, this form should only be shown if no key is stored.
  // The user needs an admin-issued init_token URL to register.
  const msg = 'Please use the registration link provided by your administrator.';
  document.getElementById('auth-error').textContent = msg;
  document.getElementById('auth-error').hidden = false;
});

// ---- init ----
main().catch(console.error);
