// app.js — glue between the WASM module and the DOM
// Requires chorgly_frontend.js (wasm-bindgen output) in the same directory.

import init, { AppState, decode_server_msg, encode_client_msg } from './pkg/chorgly_frontend.js';

const WS_URL = window.location.protocol === 'https:'
  ? `wss://${window.location.hostname}:8765/`
  : `ws://${window.location.hostname}:8765/`;

const TOKEN_KEY = 'chorgly_token';

let ws = null;
let state = null; // AppState (WASM)

// ---- bootstrap ----

async function main() {
  await init(); // initialise WASM module
  state = new AppState();

  // Q6: read token from URL query string, store it, redirect to clean URL.
  const params = new URLSearchParams(window.location.search);
  const urlToken = params.get('token');
  if (urlToken) {
    localStorage.setItem(TOKEN_KEY, urlToken);
    // Redirect to the same URL without the token in it.
    const clean = window.location.pathname + window.location.hash;
    window.history.replaceState({}, '', clean);
  }

  const saved = localStorage.getItem(TOKEN_KEY);
  if (saved) {
    showApp();
    connect(saved);
  } else {
    showAuth();
  }
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

// ---- WebSocket ----

function connect(token) {
  ws = new WebSocket(WS_URL);
  ws.binaryType = 'arraybuffer';

  ws.addEventListener('open', () => {
    send({ Auth: { token } });
  });

  ws.addEventListener('message', (ev) => {
    const bytes = new Uint8Array(ev.data);
    let msg;
    try {
      msg = decode_server_msg(bytes);
    } catch (e) {
      console.error('failed to decode server message', e);
      return;
    }
    handleServerMsg(msg, token);
  });

  ws.addEventListener('close', () => {
    // Reconnect after 3 s.
    setTimeout(() => {
      const t = localStorage.getItem(TOKEN_KEY);
      if (t) connect(t);
    }, 3000);
  });

  ws.addEventListener('error', (e) => {
    console.error('WebSocket error', e);
  });
}

function send(msg) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  try {
    const bytes = encode_client_msg(JSON.stringify(msg));
    ws.send(bytes);
  } catch (e) {
    console.error('failed to encode message', e);
  }
}

// ---- server message handler ----

function handleServerMsg(msg, token) {
  const event = state.apply(msg);

  if (event === 'auth_ok') {
    localStorage.setItem(TOKEN_KEY, token);
    document.getElementById('user-name').textContent = msg.AuthOk.user.name;
    showApp();
    send('ListAll');
    return;
  }

  if (event === 'auth_fail') {
    localStorage.removeItem(TOKEN_KEY);
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

    // Ask WASM state whether this chore's deps are actually unmet (smarter than length check).
    const blocked = state.is_chore_blocked(c.id);
    if (blocked) li.classList.add('blocked');

    const dueMs = c.next_due ? new Date(c.next_due).getTime() : null;
    if (dueMs && dueMs < now) li.classList.add('overdue');

    const title = document.createElement('span');
    title.className = 'chore-title';
    title.textContent = c.title;

    // Show assignee if set.
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
    btn.addEventListener('click', () => {
      send({ CompleteChore: { chore_id: c.id } });
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

// ---- event rendering (Q3) ----

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
    btn.addEventListener('click', () => {
      send({ TriggerEvent: { event_id: ev.id } });
    });

    li.append(name, desc, btn);
    list.append(li);
  }
}

// ---- auth form ----

document.getElementById('auth-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const token = document.getElementById('token-input').value.trim();
  if (!token) return;
  connect(token);
});

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

// Show/hide extra fields based on chore kind.
document.getElementById('chore-kind').addEventListener('change', (e) => {
  document.getElementById('field-delay').hidden    = e.target.value !== 'RecurringAfterCompletion';
  document.getElementById('field-schedule').hidden = e.target.value !== 'RecurringScheduled';
  document.getElementById('field-deadline').hidden = e.target.value !== 'WithDeadline';
});

document.getElementById('add-chore-form').addEventListener('submit', (e) => {
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

  // Q4: set permissions based on chore type.
  // Personal: only I can see / complete; I am the assignee.
  // Common: everyone sees and can complete, no specific assignee.
  let visible_to = null;
  let assignee = null;
  let can_complete = null;

  if (addingPersonal) {
    const uid = state.current_user_id();
    visible_to = [uid];
    assignee = uid;
    can_complete = [uid];
  }

  send({ AddChore: { title, kind, visible_to, assignee, can_complete, depends_on: [], depends_on_events: [] } });
  choreDialog.close();
});

// ---- add-event button (Q3) ----

const eventDialog = document.getElementById('add-event-dialog');

document.getElementById('btn-add-event').addEventListener('click', () => {
  eventDialog.showModal();
});

document.getElementById('btn-cancel-event-dialog').addEventListener('click', () => {
  eventDialog.close();
});

document.getElementById('add-event-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const name = document.getElementById('event-name').value.trim();
  const description = document.getElementById('event-description').value.trim();
  send({ AddEvent: { name, description } });
  eventDialog.close();
});

// ---- init ----
main().catch(console.error);
