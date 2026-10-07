'use strict';
/* LoVPN window. Talks only to the local lovpn-ui server on this origin.
   DOM is built with textContent only: no innerHTML, so service text can never become markup.
   All wording lives in /i18n/<language>.json; this file holds no user-visible prose. */

const SECTIONS = ['home', 'servers', 'devices', 'privacy', 'diagnostics', 'settings', 'logs', 'advanced'];
const LOCALES = [['en', 'English'], ['de', 'Deutsch']]; // endonyms: never translated
const NS = 'http://www.w3.org/2000/svg';

const app = { status: null, profiles: null, selected: null, error: null, busy: false, view: 'home', ready: false, sig: '', prevKey: null, pendingKey: null };

/* ---------- localization ---------- */

let locale = 'en';
let strings = {};
let fallback = {};

function t(key, vars) {
  let text = strings[key] ?? fallback[key];
  if (text === undefined) return key; // a missing key is visible, never silent
  if (vars) text = text.replace(/\{(\w+)\}/g, (m, name) => (name in vars ? String(vars[name]) : m));
  return text;
}
function tn(base, n, vars) {
  const rule = new Intl.PluralRules(locale).select(n) === 'one' ? 'one' : 'other';
  return t(base + '.' + rule, { n, ...vars });
}
function supportedLocale(code) { return LOCALES.some(l => l[0] === code); }
function chosenLocale() {
  const pref = lsGet('lovpn-lang') || 'auto';
  if (pref !== 'auto' && supportedLocale(pref)) return pref;
  for (const tag of (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || 'en'])) {
    const primary = String(tag).toLowerCase().split('-')[0];
    if (supportedLocale(primary)) return primary;
  }
  return 'en';
}
async function fetchStrings(code) {
  const res = await fetch('/i18n/' + code + '.json', { cache: 'no-store' });
  if (!res.ok) throw new Error('locale');
  return res.json();
}
async function loadLocale() {
  if (!Object.keys(fallback).length) { try { fallback = await fetchStrings('en'); } catch (e) { fallback = {}; } }
  locale = chosenLocale();
  try { strings = locale === 'en' ? fallback : await fetchStrings(locale); } catch (e) { locale = 'en'; strings = fallback; }
  document.documentElement.lang = locale;
  document.getElementById('skip-link').textContent = t('skip');
  document.getElementById('nav-root').setAttribute('aria-label', t('nav.label'));
  document.getElementById('rail-note').textContent = t('rail.note');
  document.getElementById('noscript-text').textContent = t('noscript');
}

/* ---------- small helpers ---------- */

function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode: the setting just won't persist */ } }

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function svg(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

class ApiError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
/* The window's own failures are localized by code; messages written by the service stay as sent. */
function describe(e) {
  const key = 'err.' + e.code;
  return (strings[key] ?? fallback[key]) !== undefined ? t(key) : e.message;
}
async function api(op, body) {
  let res;
  try {
    res = await fetch('/api/' + op, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}), cache: 'no-store',
    });
  } catch (e) {
    throw new ApiError('window.closed', 'The LoVPN window lost contact with the program that runs it.');
  }
  let json;
  try { json = await res.json(); } catch (e) { throw new ApiError('window.bad-reply', 'The window got an unreadable reply.'); }
  if (!json.ok) throw new ApiError(json.error.code, json.error.message);
  return json.data;
}

/* ---------- plain-language mapping of what the service observed ---------- */

const GROUPS = [
  { id: 'vpn', checks: ['interface', 'handshake', 'endpoint-route', 'ipv4'] },
  { id: 'dns', checks: ['dns'] },
  { id: 'ipv6', checks: ['ipv6'] },
  { id: 'kill', checks: ['firewall'] },
];
const groupName = id => t('group.' + id);

function groupState(status) {
  const out = {};
  const by = Object.fromEntries((status.checks || []).map(c => [c.name, c]));
  for (const g of GROUPS) {
    const present = g.checks.map(n => by[n]).filter(Boolean);
    let s = 'none';
    if (present.length) {
      if (present.some(c => c.status === 'fail')) s = 'fail';
      else if (present.some(c => c.status === 'unknown')) s = 'unknown';
      else if (present.every(c => c.status === 'off')) s = 'off';
      else s = 'ok';
    }
    if (g.id === 'kill' && status.state === 'blocked') s = 'blocking';
    out[g.id] = s;
  }
  return out;
}

const KNOWN_STATES = ['protected', 'degraded', 'connecting', 'blocked', 'disconnected'];
const stateOf = status => (KNOWN_STATES.includes(status.state) ? status.state : 'unknown');
function headline(status) {
  const s = stateOf(status);
  const body = status.profile && ['protected', 'degraded'].includes(s) ? t('head.' + s + '.bodyTo', { profile: status.profile }) : t('head.' + s + '.body');
  return [t('head.' + s + '.title'), body];
}
function seconds(n) { return tn('sec', n); }

/* ---------- the protection ring ---------- */

function arcPath(cx, cy, r, from, to) {
  const rad = d => (d - 90) * Math.PI / 180;
  const p = d => [cx + r * Math.cos(rad(d)), cy + r * Math.sin(rad(d))];
  const [x1, y1] = p(from), [x2, y2] = p(to);
  return `M${x1.toFixed(2)} ${y1.toFixed(2)} A${r} ${r} 0 0 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`;
}
function ring(status, states) {
  const checks = GROUPS.map(g => t('ring.check', { name: groupName(g.id), state: t('word.' + states[g.id]) })).join('; ');
  const s = svg('svg', { class: 'ring', viewBox: '0 0 280 280', role: 'img', 'aria-label': t('ring.label', { headline: headline(status)[0], checks }) });
  const order = ['kill', 'vpn', 'dns', 'ipv6']; // clockwise from the top-left quarter
  order.forEach((id, i) => {
    const start = i * 90 + 7, end = i * 90 + 83;
    s.append(svg('path', { class: 'arc', 'data-s': states[id], d: arcPath(140, 140, 118, start - 45, end - 45) }));
  });
  const word = svg('text', { x: 140, y: 138, class: 'word' }); word.textContent = t('ring.' + stateOf(status));
  const sub = svg('text', { x: 140, y: 162, class: 'sub' });
  sub.textContent = status.state === 'protected' && status.handshake_age_secs != null ? t('ring.contact', { seconds: seconds(status.handshake_age_secs) }) : (status.profile || '');
  s.append(word, sub);
  return s;
}
function glyph(id, state) {
  // A mini ring: this row's quarter in its real colour, the others faint, so the list and
  // the big ring read as one thing. Decorative: the row's text says everything.
  const order = ['kill', 'vpn', 'dns', 'ipv6'];
  const s = svg('svg', { class: 'glyph', viewBox: '0 0 28 28', 'aria-hidden': 'true', focusable: 'false' });
  order.forEach((q, i) => {
    const p = svg('path', { class: 'arc', 'data-s': q === id ? state : 'none', d: arcPath(14, 14, 9, i * 90 - 38, i * 90 + 38) });
    p.style.strokeWidth = q === id && ['ok', 'fail', 'blocking'].includes(state) ? '4.5' : '2';
    s.append(p);
  });
  return s;
}

/* ---------- announcements, notifications, toast ---------- */

function announce(text) {
  const live = document.getElementById('announcer');
  live.textContent = '';
  setTimeout(() => { live.textContent = text; }, 40);
}
function toast(message) {
  const el = document.getElementById('toast');
  el.textContent = message; el.classList.add('show');
  clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.remove('show'), 2800);
}

/* The state this window reasons about: the service being down is a state of its own. */
const keyOf = status => (!status ? null : status.service !== 'running' ? 'service' : stateOf(status));
/* Which transitions deserve a message. Never for connecting/disconnected (the user did that
   or it is routine), and only after the same state was seen on two refreshes in a row. */
function noticeFor(prev, cur) {
  if (!prev || prev === cur) return null;
  if (['degraded', 'blocked', 'unknown', 'service'].includes(cur)) return cur;
  if (cur === 'protected' && ['degraded', 'blocked', 'unknown', 'service'].includes(prev)) return 'protected';
  return null;
}
function notifyEnabled() { return lsGet('lovpn-notify') === '1' && 'Notification' in window && Notification.permission === 'granted'; }
function trackState() {
  const cur = keyOf(app.status);
  if (cur === app.prevKey) { app.pendingKey = null; return; }
  if (app.pendingKey !== cur) { app.pendingKey = cur; return; } // wait for a second sighting
  const prev = app.prevKey;
  app.prevKey = cur; app.pendingKey = null;
  if (prev === null) return; // first observation: nothing changed yet
  announce(app.status.service !== 'running' ? t('note.service') : headline(app.status)[0]);
  const kind = noticeFor(prev, cur);
  if (kind && notifyEnabled() && !(document.visibilityState === 'visible' && document.hasFocus())) {
    try { new Notification(t('note.title'), { body: t('note.' + kind), tag: 'lovpn-state' }); } catch (e) { /* the system declined */ }
  }
}

/* ---------- shared UI ---------- */

async function copy(text, done) {
  try { await navigator.clipboard.writeText(text); toast(done || t('copied')); }
  catch (e) {
    const ta = h('textarea', { 'aria-label': t('copy.label') }, text);
    document.body.append(ta); ta.select();
    try { document.execCommand('copy'); toast(done || t('copied')); } catch (e2) { toast(t('copy.manual')); }
    ta.remove();
  }
}
function errorBanner(e) {
  return h('div', { class: 'banner bad', role: 'alert' }, h('strong', null, t('error.title')), describe(e), h('details', null, h('summary', null, t('error.details')), h('p', { class: 'mono' }, e.code)));
}
async function act(label, fn, after) {
  if (app.busy) return;
  app.busy = true; app.error = null; render();
  try { const r = await fn(); if (after) after(r); } catch (e) { app.error = e; }
  app.busy = false;
  await refresh(); render();
}
function button(text, opts, onclick) {
  return h('button', { type: 'button', class: opts.class || '', disabled: opts.disabled || app.busy, 'data-fid': opts.fid || text, onclick }, text);
}

/* Dialogs: a native modal <dialog>, named by its first heading; focus returns to the opener. */
function openDialog(...nodes) {
  const d = document.getElementById('dialog');
  if (!d.open) d.dataset.opener = document.activeElement?.getAttribute?.('data-fid') || '';
  d.replaceChildren(...nodes);
  const title = d.querySelector('h2');
  if (title) { title.id = 'dialog-title'; title.setAttribute('tabindex', '-1'); d.setAttribute('aria-labelledby', 'dialog-title'); }
  if (!d.open) d.showModal();
  return d;
}
function closeDialog() {
  const d = document.getElementById('dialog');
  if (d.open) d.close();
}
function confirmDialog(title, body, confirmText, onConfirm, danger) {
  openDialog(h('h2', null, title), h('p', null, body),
    h('div', { class: 'actions' },
      button(t('btn.cancel'), {}, closeDialog),
      button(confirmText, { class: danger ? 'danger' : 'primary' }, () => { closeDialog(); onConfirm(); })));
}
function infoDialog(title, body) {
  openDialog(h('h2', null, title), h('p', null, body), h('div', { class: 'actions' }, button(t('btn.close'), { class: 'primary' }, closeDialog)));
}

/* ---------- views ---------- */

function serviceDown() {
  const hint = t(navigator.userAgent.includes('Windows') ? 'svc.hint.windows' : 'svc.hint.linux');
  return h('div', { class: 'banner bad', role: 'alert' }, h('strong', null, t('svc.title')), t('svc.body', { hint }));
}

/* Connect from Home: the default server, else the only server, else ask which. */
function connectDefault() {
  const names = (app.profiles || []).map(p => p.name);
  const target = app.selected || (names.length === 1 ? names[0] : null);
  const go = n => act('connect', () => api('connect', { profile: n }), () => toast(t('toast.connect')));
  if (target) return go(target);
  openDialog(h('h2', null, t('which.title')), h('p', null, t('which.body')),
    h('div', { class: 'actions' }, ...names.map(n => button(n, { class: 'primary' }, () => { closeDialog(); go(n); })), button(t('btn.cancel'), {}, closeDialog)));
}

function viewHome() {
  const st = app.status;
  const root = h('div');
  if (app.error) root.append(errorBanner(app.error));
  if (!st) return h('div', null, h('h1', null, t('home.starting')));
  if (st.service !== 'running') { root.append(h('h1', null, t('home.notrunning')), serviceDown()); return root; }
  if (app.profiles && app.profiles.length === 0) {
    root.append(h('h1', null, t('home.welcome')), h('p', { class: 'lead' }, t('home.welcome.lead')), onboarding());
    return root;
  }
  const states = groupState(st);
  const [title, sentence] = headline(st);
  const actions = h('div', { class: 'actions' });
  const connected = ['protected', 'degraded', 'connecting'].includes(st.state);
  if (st.state === 'degraded') actions.append(button(t('btn.repair'), { class: 'primary' }, () => act('repair', () => api('repair'), () => toast(t('toast.repair')))));
  if (connected) actions.append(button(t('btn.disconnect'), { class: st.state === 'degraded' ? '' : 'primary' }, () => act('disconnect', () => api('disconnect', {}), () => toast(t('toast.disconnected')))));
  else if (app.profiles && app.profiles.length) {
    actions.append(button(t('btn.connect'), { class: 'go' }, connectDefault));
    if (st.state === 'blocked') actions.append(button(t('btn.restore'), {}, () => confirmDialog(t('restore.title'), t('restore.body'), t('restore.confirm'), () => act('release', () => api('disconnect', { release: true })), true)));
  }
  root.append(h('div', { class: 'hero' }, ring(st, states), h('div', null, h('h1', null, title), h('p', { class: 'lead' }, sentence), actions)));
  root.append(h('ul', { class: 'checks' }, GROUPS.map(g => h('li', null, glyph(g.id, states[g.id]), h('span', { class: 'name' }, groupName(g.id)),
    h('span', { class: 'what' }, h('span', { class: 'word', 'data-s': states[g.id] }, t('word.' + states[g.id]) + '.'), ' ', t('explain.' + g.id + '.' + states[g.id]))))));
  root.append(technical(st));
  return root;
}

function technical(st) {
  const rows = (st.checks || []).map(c => h('tr', null, h('td', null, c.name), h('td', null, c.status), h('td', null, c.detail)));
  const reasons = st.reasons && st.reasons.length ? t('tech.reasons', { list: st.reasons.join(', ') }) : '';
  return h('details', null, h('summary', null, t('tech.summary')),
    st.checks && st.checks.length
      ? h('table', null, h('thead', null, h('tr', null, h('th', { scope: 'col' }, t('tech.check')), h('th', { scope: 'col' }, t('tech.result')), h('th', { scope: 'col' }, t('tech.detail')))), h('tbody', null, rows))
      : h('p', { class: 'muted' }, t('tech.none')),
    h('p', { class: 'muted' }, t('tech.state', { state: st.state, reasons, tx: st.tx_bytes ?? 0, rx: st.rx_bytes ?? 0 })));
}

function onboarding() {
  return h('section', { class: 'start' }, h('h2', null, t('onb.title')), h('p', null, t('onb.lead')),
    h('ol', null, [1, 2, 3, 4, 5].map(i => h('li', null, t('onb.' + i)))),
    button(t('btn.add'), { class: 'primary' }, () => addServer()));
}

function viewServers() {
  const root = h('div', null, h('h1', null, t('servers.title')), h('p', { class: 'lead' }, t('servers.lead')));
  if (app.error) root.append(errorBanner(app.error));
  if (!app.profiles) return root;
  const list = h('ul', { class: 'rows' });
  for (const p of app.profiles) {
    const isDefault = app.selected === p.name;
    const modeKey = 'servers.mode.' + p.kill_switch;
    const mode = (strings[modeKey] ?? fallback[modeKey]) !== undefined ? t(modeKey) : p.kill_switch;
    list.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, p.name, isDefault && h('span', { class: 'tag' }, t('servers.default'))), h('div', { class: 'muted' }, mode)),
      h('div', { class: 'row-actions' },
        button(t('btn.connect'), { fid: 'connect:' + p.name }, () => act('connect', () => api('connect', { profile: p.name }), () => toast(t('toast.connect')))),
        !isDefault && button(t('servers.makedefault'), { fid: 'use:' + p.name }, () => act('use', () => api('use', { name: p.name }), () => toast(t('toast.default_is', { name: p.name })))),
        button(t('servers.check'), { fid: 'test:' + p.name }, () => act('test', () => api('test', { name: p.name }), r => infoDialog(t('servers.check.title'), r.reachability === 'not-tested' ? t('servers.check.intact') : t('servers.check.done')))),
        button(t('servers.remove'), { class: 'danger', fid: 'remove:' + p.name }, () => confirmDialog(t('servers.remove.title', { name: p.name }), t('servers.remove.body'), t('servers.remove.confirm'), () => act('remove', () => api('remove', { name: p.name }), () => toast(t('toast.removed', { name: p.name }))), true)))));
  }
  root.append(list.children.length ? list : h('p', { class: 'muted' }, t('servers.none')), h('div', { class: 'actions' }, button(t('btn.add'), { class: 'primary' }, () => addServer())));
  return root;
}

/* Add-a-server wizard: name, device key, profile, check + connect. */
function addServer() {
  const w = { name: '', pub: null, step: 1, err: null, busy: false, drawn: 0 };
  const frame = (title, ...body) => {
    const d = openDialog(...[h('h2', null, title), w.err && h('p', { class: 'err', role: 'alert', id: 'wiz-err' }, t('wiz.error', { message: describe(w.err), code: w.err.code })), ...body].filter(Boolean));
    return d;
  };
  const run = async fn => { w.busy = true; w.err = null; draw(); try { await fn(); } catch (e) { w.err = e; } w.busy = false; draw(); };
  const close = () => { closeDialog(); refresh().then(render); };
  const focusStep = d => { if (w.drawn !== w.step) { w.drawn = w.step; d.querySelector('h2')?.focus(); } };
  function draw() {
    if (w.step === 1) {
      const input = h('input', { type: 'text', id: 'srvname', value: w.name, autocomplete: 'off', spellcheck: 'false', 'aria-describedby': 'nh' + (w.err ? ' wiz-err' : ''), 'aria-invalid': w.err ? 'true' : false });
      frame(t('wiz.name.title'), h('label', { for: 'srvname' }, t('wiz.name.label')), input,
        h('p', { class: 'hint', id: 'nh' }, t('wiz.name.hint')),
        h('div', { class: 'actions' }, button(t('btn.cancel'), {}, close), button(t('wiz.continue'), { class: 'primary', disabled: w.busy }, () => {
          w.name = input.value.trim();
          if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(w.name)) { w.err = { code: 'name.invalid', message: t('wiz.name.invalid') }; draw(); return; }
          w.step = 2; w.err = null; draw();
        })));
      w.drawn = 1; (document.getElementById('srvname'))?.focus();
    } else if (w.step === 2) {
      const d = frame(t('wiz.key.title'),
        h('p', null, t(navigator.userAgent.includes('Windows') ? 'wiz.key.body.windows' : 'wiz.key.body.linux')),
        w.pub ? h('div', null, h('p', null, t('wiz.key.send')), h('div', { class: 'keybox' }, w.pub),
          h('div', { class: 'actions' }, button(t('wiz.key.copy'), {}, () => copy(w.pub, t('wiz.key.copied'))), button(t('wiz.key.sent'), { class: 'primary' }, () => { w.step = 3; w.err = null; draw(); })))
          : h('div', { class: 'actions' }, button(t('wiz.key.have'), { class: 'quiet' }, () => { w.step = 3; draw(); }),
            button(t('wiz.key.create'), { class: 'primary', disabled: w.busy }, () => run(async () => { const r = await api('identity', { name: w.name }); w.pub = r.public_key; }))));
      focusStep(d);
    } else if (w.step === 3) {
      const file = h('input', { type: 'file', id: 'pf', accept: '.toml,text/plain' });
      const text = h('textarea', { id: 'pt', 'aria-describedby': 'ph', spellcheck: 'false' });
      const key = h('input', { type: 'text', id: 'sk', autocomplete: 'off', spellcheck: 'false', 'aria-describedby': 'kh' });
      file.addEventListener('change', async () => { const f = file.files[0]; if (f && f.size < 70000) text.value = await f.text(); });
      const d = frame(t('wiz.profile.title'),
        h('label', { for: 'pf' }, t('wiz.profile.file')), file,
        h('label', { for: 'pt' }, t('wiz.profile.paste')), text, h('p', { class: 'hint', id: 'ph' }, t('wiz.profile.hint')),
        h('label', { for: 'sk' }, t('wiz.profile.key')), key,
        h('p', { class: 'hint', id: 'kh' }, t('wiz.profile.keyhint')),
        h('div', { class: 'actions' }, button(t('btn.cancel'), {}, close), button(t('wiz.profile.import'), { class: 'primary', disabled: w.busy }, () => run(async () => {
          await api('import', { name: w.name, profile: text.value, expected_server_key: key.value.trim() }); w.step = 4;
        }))));
      focusStep(d);
    } else {
      const d = frame(t('wiz.done.title'), h('p', null, t('wiz.done.body')),
        h('div', { class: 'actions' }, button(t('wiz.done.notnow'), {}, close), button(t('btn.connect'), { class: 'go', disabled: w.busy }, () => run(async () => { await api('connect', { profile: w.name }); close(); location.hash = '#/privacy'; }))));
      focusStep(d);
    }
  }
  draw();
}

function viewDevices() {
  const root = h('div', null, h('h1', null, t('devices.title')), h('p', { class: 'lead' }, t('devices.lead')));
  if (app.error) root.append(errorBanner(app.error));
  if (!app.profiles) return root;
  const list = h('ul', { class: 'rows' });
  for (const p of app.profiles) {
    const out = h('div', { class: 'muted', 'aria-live': 'polite' }, t('devices.nokey'));
    list.append(h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, t('devices.on', { name: p.name })), out),
      h('div', { class: 'row-actions' }, button(t('devices.show'), { fid: 'key:' + p.name }, async () => { try { const r = await api('device', { name: p.name }); out.replaceChildren(h('span', { class: 'mono' }, r.public_key)); out.dataset.key = r.public_key; } catch (e) { out.textContent = describe(e); } }))));
  }
  root.append(list.children.length ? list : h('p', { class: 'muted' }, t('devices.none')));
  const [a, b] = t('devices.other.body', { create: '\u0001', revoke: '\u0002', rotate: '\u0003' }).split(/[\u0001\u0002\u0003]/).length === 4 ? [null, null] : [null, null];
  void a; void b;
  const parts = t('devices.other.body', { create: '\u0001', revoke: '\u0002', rotate: '\u0003' }).split(/([\u0001\u0002\u0003])/);
  const names = { '\u0001': 'lovpn-server peer create', '\u0002': 'peer revoke', '\u0003': 'peer rotate' };
  root.append(h('h2', null, t('devices.other.title')), h('p', null, parts.map(x => (names[x] ? h('code', null, names[x]) : x))));
  return root;
}

function viewPrivacy() {
  const st = app.status;
  const root = h('div', null, h('h1', null, t('privacy.title')), h('p', { class: 'lead' }, t('privacy.lead')));
  if (!st || st.service !== 'running') { root.append(serviceDown()); return root; }
  const states = groupState(st);
  const rows = GROUPS.map(g => h('tr', null, h('td', null, groupName(g.id)), h('td', null, h('span', { class: 'word', 'data-s': states[g.id] }, t('word.' + states[g.id]))), h('td', null, t('explain.' + g.id + '.' + states[g.id]))));
  root.append(h('table', { class: 'stack' }, h('thead', null, h('tr', null, h('th', { scope: 'col' }, t('privacy.protection')), h('th', { scope: 'col' }, t('privacy.status')), h('th', { scope: 'col' }, t('privacy.means')))), h('tbody', null, rows)));
  root.append(h('h2', null, t('privacy.not.title')));
  root.append(h('table', { class: 'stack' }, h('tbody', null,
    h('tr', null, h('td', null, t('privacy.telemetry')), h('td', null, t('privacy.telemetry.v')), h('td', null, t('privacy.telemetry.d'))),
    h('tr', null, h('td', null, t('privacy.account')), h('td', null, t('privacy.account.v')), h('td', null, t('privacy.account.d'))),
    h('tr', null, h('td', null, t('privacy.network')), h('td', null, t('privacy.network.v')), h('td', null, t('privacy.network.d'))))));
  root.append(h('p', { class: 'muted' }, t('privacy.dnsnote')));
  return root;
}

function viewDiagnostics() {
  const st = app.status;
  const root = h('div', null, h('h1', null, t('diag.title')), h('p', { class: 'lead' }, t('diag.lead')));
  if (app.error) root.append(errorBanner(app.error));
  if (!st || st.service !== 'running') { root.append(serviceDown()); return root; }
  root.append(h('div', { class: 'actions' },
    button(t('diag.again'), {}, () => act('refresh', async () => {})),
    button(t('diag.copy'), { class: 'primary' }, async () => { try { const r = await api('diagnostics'); const text = JSON.stringify(r, null, 2); app.diag = text; await copy(text, t('diag.copied')); render(); } catch (e) { app.error = e; render(); } })));
  root.append(h('p', { class: 'muted' }, t('diag.note')));
  if (app.diag) root.append(h('pre', { class: 'log', tabindex: '0', 'aria-label': t('diag.copy') }, app.diag));
  root.append(h('h2', null, t('diag.checks')), technical(st).querySelector('table') || h('p', { class: 'muted' }, t('tech.none')));
  root.append(h('p', { class: 'muted' }, t('diag.summary', { age: st.handshake_age_secs != null ? seconds(st.handshake_age_secs) : t('diag.none'), mode: st.kill_switch || t('diag.none'), armed: st.kill_switch_armed ? t('diag.armed') : '' })));
  return root;
}

function viewSettings() {
  const theme = lsGet('lovpn-theme') || 'system';
  const lang = lsGet('lovpn-lang') || 'auto';
  const radios = (name, label, current, options, onchange) => h('div', { class: 'radios', role: 'radiogroup', 'aria-label': label }, options.map(([v, text]) => h('label', null, h('input', { type: 'radio', name, value: v, checked: current === v, onchange: () => onchange(v) }), h('span', null, text))));
  const root = h('div', null, h('h1', null, t('settings.title')), h('p', { class: 'lead' }, t('settings.lead')));
  if (app.error) root.append(errorBanner(app.error));
  root.append(h('h2', null, t('settings.appearance')),
    radios('theme', t('settings.appearance'), theme, [['system', t('theme.system')], ['light', t('theme.light')], ['dark', t('theme.dark')]], v => { lsSet('lovpn-theme', v); applyTheme(); }));
  root.append(h('h2', null, t('settings.language')),
    radios('lang', t('settings.language'), lang, [['auto', t('lang.auto')], ...LOCALES], async v => { lsSet('lovpn-lang', v); await loadLocale(); lastKey = ''; await render(); }),
    h('p', { class: 'hint' }, t('lang.note')));
  root.append(h('h2', null, t('settings.notify')), notifySetting());
  if (app.profiles && app.profiles.length) {
    const sel = h('select', { id: 'defsrv', onchange: e => act('use', () => api('use', { name: e.target.value }), () => toast(t('toast.default'))) }, app.profiles.map(p => h('option', { value: p.name, selected: p.name === app.selected }, p.name)));
    if (!app.selected) sel.prepend(h('option', { value: '', selected: true, disabled: true }, t('settings.default.choose')));
    root.append(h('h2', null, t('settings.default')), h('label', { for: 'defsrv' }, t('settings.default.label')), sel, h('p', { class: 'hint' }, t('settings.default.hint')));
  }
  root.append(h('h2', null, t('settings.kill.title')), h('p', null, t('settings.kill.body')));
  root.append(h('h2', null, t('settings.about')), h('p', null, t('settings.about.body')));
  return root;
}

function notifySetting() {
  const supported = 'Notification' in window;
  const wrap = h('div');
  const hint = h('p', { class: 'hint', id: 'notify-hint' }, supported ? t('notify.hint') : t('notify.unsupported'));
  const box = h('input', { type: 'checkbox', id: 'notify', 'aria-describedby': 'notify-hint', disabled: !supported, checked: supported && lsGet('lovpn-notify') === '1' && Notification.permission === 'granted' });
  box.addEventListener('change', async () => {
    if (!box.checked) { lsSet('lovpn-notify', '0'); return; }
    // The permission prompt must come from this click: the browser decides, not the page.
    let granted = Notification.permission === 'granted';
    if (!granted && Notification.permission !== 'denied') { try { granted = (await Notification.requestPermission()) === 'granted'; } catch (e) { granted = false; } }
    if (granted) lsSet('lovpn-notify', '1');
    else { box.checked = false; lsSet('lovpn-notify', '0'); hint.textContent = t('notify.denied'); hint.setAttribute('role', 'alert'); }
  });
  wrap.append(h('label', { class: 'check', for: 'notify' }, box, h('span', null, t('notify.label'))), hint);
  return wrap;
}

async function viewLogs() {
  const root = h('div', null, h('h1', null, t('logs.title')), h('p', { class: 'lead' }, t('logs.lead')));
  const pre = h('pre', { class: 'log', tabindex: '0', 'aria-label': t('logs.label') }, t('logs.loading'));
  root.append(h('div', { class: 'actions' }, button(t('btn.refresh'), {}, () => loadLogs(pre)), button(t('btn.copy'), {}, () => copy(pre.textContent, t('logs.copied')))), pre);
  loadLogs(pre);
  return root;
}
async function loadLogs(pre) {
  try { const r = await api('logs', { lines: 200 }); pre.textContent = r.lines.length ? r.lines.map(readableLog).join('\n') : t('logs.empty'); pre.scrollTop = pre.scrollHeight; }
  catch (e) { pre.textContent = describe(e) + '\n(' + e.code + ')'; }
}

/* One service log line (JSON) as: time, what happened, result. Non-JSON lines pass through. */
function readableLog(line) {
  try {
    const e = JSON.parse(line);
    const time = e.ts ? new Date(e.ts * 1000).toLocaleTimeString(locale) : '';
    const what = e.op ? e.op : e.event;
    return [time, what, e.code ? '(' + e.code + ')' : ''].filter(Boolean).join('  ');
  } catch (err) { return line; }
}

function viewAdvanced() {
  const root = h('div', null, h('h1', null, t('adv.title')), h('p', { class: 'lead' }, t('adv.lead')));
  if (app.error) root.append(errorBanner(app.error));
  const row = (title, text, control) => h('li', null, h('div', { class: 'grow' }, h('div', { class: 'title' }, title), h('div', { class: 'muted' }, text)), control);
  root.append(h('ul', { class: 'rows' },
    row(t('adv.reconnect'), t('adv.reconnect.d'), button(t('adv.reconnect'), {}, () => act('reconnect', () => api('reconnect'), () => toast(t('toast.reconnected'))))),
    row(t('adv.repair'), t('adv.repair.d'), button(t('adv.repair'), {}, () => act('repair', () => api('repair'), () => toast(t('toast.repair'))))),
    row(t('adv.reset'), t('adv.reset.d'), button(t('adv.reset'), { class: 'danger' }, () => confirmDialog(t('adv.reset.title'), t('adv.reset.body'), t('adv.reset'), () => act('reset', () => api('reset'), () => toast(t('toast.reset'))), true)))));
  root.append(h('h2', null, t('adv.todo')), h('ul', { class: 'todo' },
    ['ipv6', 'split', 'lan'].map(k => h('li', null, h('strong', null, t('adv.todo.' + k)), t('adv.todo.' + k + '.d')))));
  return root;
}

/* ---------- plumbing ---------- */

function applyTheme() {
  const th = lsGet('lovpn-theme');
  if (th === 'light' || th === 'dark') document.documentElement.dataset.theme = th; else delete document.documentElement.dataset.theme;
}

const VIEWS = { home: viewHome, servers: viewServers, devices: viewDevices, privacy: viewPrivacy, diagnostics: viewDiagnostics, settings: viewSettings, logs: viewLogs, advanced: viewAdvanced };

async function refresh() {
  try {
    app.status = await api('status');
    if (app.status.service === 'running') {
      const p = await api('profiles');
      app.profiles = p.profiles || []; app.selected = p.selected || null;
    } else { app.profiles = null; }
  } catch (e) { app.status = { service: 'unreachable', state: 'unknown' }; if (e.code === 'window.closed') app.error = e; }
  trackState();
}

let lastKey = '';
async function render(opts) {
  const focusId = document.activeElement?.getAttribute?.('data-fid');
  const hadFocusInMain = document.getElementById('main').contains(document.activeElement);
  const nav = document.getElementById('nav');
  nav.replaceChildren(...SECTIONS.map(id => h('li', null, h('a', { href: '#/' + id, 'aria-current': app.view === id ? 'page' : false }, t('nav.' + id)))));
  const main = document.getElementById('main');
  main.setAttribute('aria-busy', app.busy ? 'true' : 'false');
  const node = await VIEWS[app.view]();
  main.replaceChildren(node);
  const heading = main.querySelector('h1');
  if (heading) heading.setAttribute('tabindex', '-1');
  if (app.view !== lastKey) {
    lastKey = app.view;
    document.title = t('title.page', { section: t('nav.' + app.view) });
    if (opts && opts.moveFocus && heading) heading.focus();
  } else if (focusId && hadFocusInMain) {
    // The polling re-render replaced the buttons; put keyboard focus back where it was.
    const again = [...main.querySelectorAll('[data-fid]')].find(el => el.getAttribute('data-fid') === focusId);
    if (again && !again.disabled) again.focus();
  }
  app.sig = signature();
}
function signature() { return JSON.stringify([app.status, app.profiles, app.selected, app.error && app.error.code, app.busy, locale]); }

function route(initial) {
  const id = (location.hash.replace(/^#\//, '') || 'home');
  app.view = VIEWS[id] ? id : 'home'; app.error = null; render({ moveFocus: !initial });
}

window.addEventListener('hashchange', () => route(false));
document.getElementById('dialog').addEventListener('close', () => {
  const id = document.getElementById('dialog').dataset.opener;
  if (!id) return;
  const again = [...document.querySelectorAll('[data-fid]')].find(el => el.getAttribute('data-fid') === id);
  if (again) again.focus();
});
applyTheme();
(async function start() {
  await loadLocale();
  await refresh(); route(true); app.ready = true;
  setInterval(async () => {
    if (document.hidden || app.busy || document.getElementById('dialog').open) return;
    const before = signature();
    await refresh();
    // Re-render only when something changed: a poll must never reset a half-read page,
    // an opened "Technical details", a text selection or screen-reader position.
    if (signature() !== before && ['home', 'privacy', 'diagnostics', 'servers', 'settings', 'devices'].includes(app.view) && !document.activeElement?.closest('select, input, textarea')) render();
  }, 2500);
  setInterval(() => api('ping').catch(() => {}), 8000);
  api('ping').catch(() => {});
})();
