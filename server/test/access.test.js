// Private display links + device pairing: access-control matrix over every display endpoint (private vs open),
// key regeneration, pairing lifecycle (create / claim / expire / single use / wrong code / rate limits / session id),
// redaction, migration. Runs the real app (server/app.js createApp) on a random port.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as store from '../store.js';
import { defaultConfig, defaultScreenProfile } from '../core/defaults.js';
import { ensurePassword, hashPassword } from '../auth.js';
import { createApp } from '../app.js';
import { closeAll, broadcast, listClients } from '../sse.js';
import { _resetDisplays, setServerVersion, listDisplays } from '../displays.js';
import { _resetAnnouncements } from '../announce.js';
import { _resetActivityThrottle, logActivity, listActivity } from '../activity.js';
import { createToken } from '../tokens.js';
import {
  syncDisplayKeys, onDisplayAccessConfig, listDisplayLinks, KEY_RE, DEVICE_TOKEN_RE, _resetDisplayAccess, revalidateStreams,
  isLoopbackClient, listDevices,
} from '../displayAccess.js';
import {
  startPairing, pairingStatus, claimPairing, displayAddress, normalizeCode, _resetPairing, _pendingCount, CODE_ALPHABET, CODE_LENGTH,
  PAIR_TTL_MS, WAITING_GRACE_MS, CLAIM_FAIL_LIMIT, CLAIM_FAIL_GLOBAL, START_LIMIT, MAX_PENDING_PER_ADDRESS,
} from '../pairing.js';
import { redactSecrets } from '../core/activityCore.js';

const realFetch = globalThis.fetch;
// No network in tests: Open-Meteo / picsum calls fail fast (the display endpoints then answer 502 / fall back).
const offlineFetch = (url, opts) => (/^https?:\/\/127\.0\.0\.1[:/]/.test(String(url)) ? realFetch(url, opts) : Promise.reject(new Error('offline test')));

async function withServer(fn, { mode = 'private' } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marco-access-'));
  globalThis.fetch = offlineFetch;
  const c = defaultConfig();
  c.calendar.sources = [];
  c.news.feeds = [];
  c.security.displayAccess = mode;
  c.screens[0].background.source = 'gallery';
  c.screens.push(defaultScreenProfile({ id: 's_kitchen', slug: 'kitchen', name: 'Kitchen' }));
  c.screens[1].background.source = 'gallery';
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(c));
  fs.writeFileSync(path.join(dir, 'secrets.json'), JSON.stringify({ passwordHash: await hashPassword('secret-pass-123'), passwordIsDefault: false }));
  fs.mkdirSync(path.join(dir, 'photos', '.thumbs'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'photos', 'family.jpg'), 'jpeg');
  fs.writeFileSync(path.join(dir, 'photos', '.thumbs', 'family.jpg'), 'thumb');
  const dist = path.join(dir, 'dist');
  fs.mkdirSync(path.join(dist, 'admin'), { recursive: true });
  fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>display</title>');
  fs.writeFileSync(path.join(dist, 'admin', 'index.html'), '<!doctype html><title>admin</title>');
  store.initStore(dir);
  _resetDisplays();
  _resetAnnouncements();
  _resetPairing();
  _resetActivityThrottle();
  _resetDisplayAccess();
  setServerVersion('0.3.0');
  await ensurePassword();
  syncDisplayKeys();
  // Same order as server/index.js: access sync, then the 'config' broadcast to every stream still registered.
  const onConfig = (cfg, prev) => { onDisplayAccessConfig(cfg, prev); broadcast('config', { revision: cfg.revision }); };
  store.events.on('config', onConfig);
  const app = createApp({ version: '0.3.0', dist });
  const server = await new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, url, { body, headers = {}, cookie = '' } = {}) => {
    const r = await realFetch(base + url, {
      method,
      headers: { ...headers, ...(cookie ? { cookie } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: r.status, json, headers: r.headers, text, setCookie: r.headers.getSetCookie?.() || [] };
  };
  const login = async () => {
    const r = await call('POST', '/api/auth/login', { body: { password: 'secret-pass-123' } });
    assert.equal(r.status, 200);
    return r.setCookie.map((x) => x.split(';')[0]).join('; ');
  };
  /** Open an SSE stream; returns { status, events(), next(name), close() }. */
  const stream = async (url, { headers = {}, cookie = '' } = {}) => {
    const ctl = new AbortController();
    const r = await realFetch(base + url, { headers: { ...headers, ...(cookie ? { cookie } : {}) }, signal: ctl.signal });
    let buf = '';
    let ended = false;
    const waiters = [];
    const parse = () => buf.split('\n\n').filter((b) => b.startsWith('event:')).map((b) => {
      const [ev, data] = b.split('\n');
      return { event: ev.slice(7), data: JSON.parse(data.slice(6)) };
    });
    if (r.status === 200) {
      (async () => {
        try {
          for await (const chunk of r.body) {
            buf += Buffer.from(chunk).toString();
            waiters.forEach((w) => w());
          }
        } catch { /* aborted */ }
        ended = true;
        waiters.forEach((w) => w());
      })();
    } else await r.text();
    const next = (name, ms = 2000) => new Promise((resolve, reject) => {
      const t0 = Date.now();
      const check = () => {
        const hit = parse().find((e) => e.event === name);
        if (hit) return resolve(hit);
        if (Date.now() - t0 > ms) return reject(new Error(`no ${name} event`));
        waiters.push(check);
        setTimeout(check, 50);
      };
      check();
    });
    return { status: r.status, events: parse, next, ended: () => ended, close: () => ctl.abort() };
  };
  try {
    await fn({ call, login, stream, dir, base });
  } finally {
    store.events.off('config', onConfig);
    closeAll();
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
    globalThis.fetch = realFetch;
  }
}

const keyOf = (slug) => listDisplayLinks().find((l) => l.slug === slug).key;

// Every display-facing endpoint. `query` = credential travels as ?k= (EventSource / <img>), else X-Marco-Key.
const ENDPOINTS = [
  { name: 'display config', method: 'GET', url: '/api/display/config' },
  { name: 'events', method: 'GET', url: '/api/events' },
  { name: 'weather', method: 'GET', url: '/api/weather', upstream: true },
  { name: 'news', method: 'GET', url: '/api/news' },
  { name: 'photos', method: 'GET', url: '/api/photos' },
  { name: 'countdowns', method: 'GET', url: '/api/countdowns' },
  { name: 'heartbeat', method: 'POST', url: '/api/display/heartbeat', body: { clientId: 'kiosk-test-1' } },
  { name: 'poll', method: 'GET', url: '/api/display/poll?client=kiosk-test-3' },
  { name: 'stream', method: 'GET', url: '/api/stream?client=kiosk-test-2', sse: true, query: true },
  { name: 'photo file', method: 'GET', url: '/media/photos/family.jpg', query: true },
  // thumbnails are for the admin's gallery grid: a display credential or open mode gets 404 (adminOnly)
  { name: 'thumbnail', method: 'GET', url: '/media/thumbs/family.jpg', query: true, adminOnly: true },
];

/** Status of one endpoint with a credential / cookie / extra headers. */
async function hit(ctx, ep, { cred = '', cookie = '', headers = {} } = {}) {
  let url = ep.url;
  const h = { ...headers };
  if (cred) {
    if (ep.query) url += `${url.includes('?') ? '&' : '?'}k=${encodeURIComponent(cred)}`;
    else h['x-marco-key'] = cred;
  }
  if (ep.sse) {
    const s = await ctx.stream(url, { headers: h, cookie });
    s.close();
    return s.status;
  }
  return (await ctx.call(ep.method, url, { body: ep.body, headers: h, cookie })).status;
}
const allowed = (ep, status, { session = false } = {}) => (ep.adminOnly && !session ? status === 404 : ep.upstream ? ![401, 403].includes(status) : status === 200);

test('private mode: access matrix (no key 401, valid key, revoked key 403, device token, admin session)', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const kitchenKey = keyOf('kitchen');
    assert.match(kitchenKey, KEY_RE);
    // a paired device for the kitchen
    const st = await ctx.call('POST', '/api/pair/start', { body: {} });
    const claim = await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code: st.json.code, screenId: 's_kitchen', name: 'Hall tablet', confirm: true } });
    assert.equal(claim.status, 200, claim.text);
    const deviceToken = (await ctx.call('POST', '/api/pair/status', { body: { sessionId: st.json.sessionId } })).json.token;
    assert.match(deviceToken, DEVICE_TOKEN_RE);

    for (const ep of ENDPOINTS) {
      assert.equal(await hit(ctx, ep), 401, `${ep.name}: no key → 401`);
      assert.ok(allowed(ep, await hit(ctx, ep, { cred: kitchenKey })), `${ep.name}: valid key`);
      assert.ok(allowed(ep, await hit(ctx, ep, { cred: kitchenKey.toUpperCase() })), `${ep.name}: key is case-insensitive`);
      assert.ok(allowed(ep, await hit(ctx, ep, { cred: deviceToken })), `${ep.name}: device token`);
      assert.ok(allowed(ep, await hit(ctx, ep, { cookie }), { session: true }), `${ep.name}: admin session`);
      assert.equal(await hit(ctx, ep, { cred: '00000000-0000-4000-8000-000000000000' }), 403, `${ep.name}: unknown key → 403`);
      assert.equal(await hit(ctx, ep, { cred: `md_${'A'.repeat(43)}` }), 403, `${ep.name}: unknown device token → 403`);
      assert.equal(await hit(ctx, ep, { cred: 'not-a-key' }), 403, `${ep.name}: garbage → 403`);
      // an invalid credential is refused even together with an admin session (no silent fallback)
      assert.equal(await hit(ctx, ep, { cred: '00000000-0000-4000-8000-000000000000', cookie }), 403, `${ep.name}: bad key + session → 403`);
    }
    // ?k= is only accepted where headers are impossible (SSE, media), never on the JSON API
    assert.equal((await ctx.call('GET', `/api/display/config?k=${kitchenKey}`)).status, 401);
    // the key decides the screen; ?screen= cannot read another screen with it
    const cfg = await ctx.call('GET', '/api/display/config?screen=living-room', { headers: { 'x-marco-key': kitchenKey } });
    assert.equal(cfg.json.screenId, 's_kitchen');
    assert.equal('screenFallback' in cfg.json, false);
    assert.match(cfg.headers.get('cache-control'), /private/);
    assert.match(cfg.headers.get('cache-control'), /no-store/);
    assert.equal(cfg.headers.get('referrer-policy'), 'no-referrer');
    const dev = await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': deviceToken } });
    assert.equal(dev.json.screenId, 's_kitchen');
    // 401 / 403 bodies carry a code for the display and no data
    const no = await ctx.call('GET', '/api/events');
    assert.equal(no.json.code, 'key_required');
    assert.deepEqual(Object.keys(no.json).sort(), ['code', 'error']);
    assert.equal((await ctx.call('GET', '/api/events', { headers: { 'x-marco-key': 'nope' } })).json.code, 'invalid_key');
    // admin preview iframe (session + ?screen=&preview=1) keeps working
    assert.equal((await ctx.call('GET', '/api/display/config?screen=kitchen&preview=1', { cookie })).json.screenId, 's_kitchen');
    // health stays public; webhooks keep using API tokens
    assert.equal((await ctx.call('GET', '/api/health')).status, 200);
    const { token } = createToken('Home Assistant');
    assert.equal((await ctx.call('GET', '/api/hooks/ping', { headers: { authorization: `Bearer ${token}` } })).status, 200);
    assert.equal((await ctx.call('GET', '/api/hooks/ping', { headers: { 'x-marco-key': kitchenKey } })).status, 401);
    // the private link page itself: display HTML, never cached, no referrer, not indexed
    const page = await ctx.call('GET', `/d/${kitchenKey}`);
    assert.equal(page.status, 200);
    assert.match(page.text, /display/);
    assert.match(page.headers.get('cache-control'), /no-store/);
    assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
    assert.match(page.headers.get('x-robots-tag'), /noindex/);
    // heartbeat with a key registers the bound screen and how it got in
    await ctx.call('POST', '/api/display/heartbeat', { headers: { 'x-marco-key': kitchenKey }, body: { clientId: 'kiosk-kitchen', screen: 'living-room' } });
    const reg = listDisplays().find((d) => d.clientId === 'kiosk-kitchen');
    assert.equal(reg.screenId, 's_kitchen');
    assert.equal(reg.access, 'key');
  });
});

test('open mode (legacy LAN): no key needed on the LAN, Internet media still 404, keys still bind and bad keys fail', async () => {
  await withServer(async (ctx) => {
    const kitchenKey = keyOf('kitchen');
    for (const ep of ENDPOINTS) {
      assert.ok(allowed(ep, await hit(ctx, ep)), `${ep.name}: open without key`);
      assert.ok(allowed(ep, await hit(ctx, ep, { cred: kitchenKey })), `${ep.name}: open + valid key`);
      assert.equal(await hit(ctx, ep, { cred: '00000000-0000-4000-8000-000000000000' }), 403, `${ep.name}: open + revoked key → 403`);
    }
    const internet = { 'x-forwarded-for': '203.0.113.9' };
    assert.equal((await ctx.call('GET', '/media/photos/family.jpg', { headers: internet })).status, 404);
    assert.equal((await ctx.call('GET', `/media/photos/family.jpg?k=${kitchenKey}`, { headers: internet })).status, 200);
    assert.equal((await ctx.call('GET', '/api/display/config?screen=kitchen')).json.screenId, 's_kitchen');
    assert.equal((await ctx.call('GET', '/api/display/config?screen=living-room', { headers: { 'x-marco-key': kitchenKey } })).json.screenId, 's_kitchen');
  }, { mode: 'open' });
});

test('switching open → private disconnects keyless displays (revoked: key_required); keyed ones stay', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const open = await ctx.stream('/api/stream?client=kiosk-open');
    const keyed = await ctx.stream(`/api/stream?client=kiosk-keyed&k=${keyOf('kitchen')}`);
    await open.next('hello');
    await keyed.next('hello');
    const cfg = (await ctx.call('GET', '/api/admin/config', { cookie })).json;
    cfg.security.displayAccess = 'private';
    assert.equal((await ctx.call('PUT', '/api/admin/config', { cookie, body: cfg })).status, 200);
    const ev = await open.next('revoked');
    assert.equal(ev.data.code, 'key_required');
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(!keyed.events().some((e) => e.event === 'revoked'));
    assert.equal((await ctx.call('GET', '/api/events')).status, 401);
    open.close();
    keyed.close();
  }, { mode: 'open' });
});

test('regenerate link: old key revoked at once, connected displays told via SSE, new key works, keys never logged', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    assert.equal((await ctx.call('GET', '/api/admin/display-links')).status, 401);
    const links = (await ctx.call('GET', '/api/admin/display-links', { cookie })).json;
    assert.equal(links.mode, 'private');
    assert.equal(links.links.length, 2);
    const old = links.links.find((l) => l.screenId === 's_kitchen');
    assert.equal(old.path, `/d/${old.key}`);
    const other = links.links.find((l) => l.screenId === 's_main').key;
    const s = await ctx.stream(`/api/stream?client=kiosk-kitchen&k=${old.key}`);
    const s2 = await ctx.stream(`/api/stream?client=kiosk-living&k=${other}`);
    assert.equal((await s.next('hello')).data.screenId, 's_kitchen');
    await s2.next('hello');
    // CSRF: cross-origin regenerate refused
    assert.equal((await ctx.call('POST', '/api/admin/display-links/s_kitchen/regenerate', { cookie, body: {}, headers: { origin: 'https://evil.example' } })).status, 403);
    const r = await ctx.call('POST', '/api/admin/display-links/s_kitchen/regenerate', { cookie, body: {} });
    assert.equal(r.status, 200);
    const fresh = r.json.link.key;
    assert.notEqual(fresh, old.key);
    assert.match(fresh, KEY_RE);
    assert.equal((await s.next('revoked')).data.code, 'invalid_key');
    await new Promise((res) => setTimeout(res, 100));
    assert.ok(s.ended(), 'stream closed by the server');
    assert.ok(!s2.events().some((e) => e.event === 'revoked'), 'other screens untouched');
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': old.key } })).status, 403);
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': fresh } })).json.screenId, 's_kitchen');
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': other } })).status, 200);
    assert.equal((await ctx.call('POST', '/api/admin/display-links/s_nope/regenerate', { cookie, body: {} })).status, 404);
    // keys are stored server-side only (secrets.json, 0600), never in config / exports / activity
    const secrets = fs.readFileSync(path.join(ctx.dir, 'secrets.json'), 'utf8');
    assert.ok(secrets.includes(fresh));
    assert.ok(!fs.readFileSync(path.join(ctx.dir, 'config.json'), 'utf8').includes(fresh));
    assert.ok(!JSON.stringify((await ctx.call('GET', '/api/admin/config', { cookie })).json).includes(fresh));
    const activity = fs.readFileSync(path.join(ctx.dir, 'activity.jsonl'), 'utf8');
    assert.match(activity, /display\.link_regenerated/);
    for (const k of [old.key, fresh, other]) assert.ok(!activity.includes(k), 'key not in the activity log');
    s2.close();
  });
});

test('screens deleted → their links stop working; their paired devices are revoked', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const kitchenKey = keyOf('kitchen');
    const st = startPairing({ ip: '192.168.1.40', get: () => '' });
    const out = claimPairing({ ip: '127.0.0.1', session: { epoch: 'x', user: { email: 'admin' } } }, { code: st.code, screenId: 's_kitchen', confirm: true });
    assert.ok(out.device);
    const token = pairingStatus(st.sessionId).token;
    const cfg = (await ctx.call('GET', '/api/admin/config', { cookie })).json;
    cfg.screens = cfg.screens.filter((s) => s.id !== 's_kitchen');
    assert.equal((await ctx.call('PUT', '/api/admin/config', { cookie, body: cfg })).status, 200);
    assert.equal((await ctx.call('GET', '/api/events', { headers: { 'x-marco-key': kitchenKey } })).status, 403);
    // never moved to another screen: the device token stops working
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': token } })).status, 403);
    assert.ok(!listDevices().some((d) => d.id === out.device.id));
  });
});

test('pairing over HTTP: start → claim (admin) → status hands the token once → device works → revoke', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const st = await ctx.call('POST', '/api/pair/start', { body: {} });
    assert.equal(st.status, 200);
    assert.match(st.headers.get('cache-control'), /no-store/);
    const { sessionId, code } = st.json;
    assert.equal(code.length, CODE_LENGTH);
    for (const ch of code) assert.ok(CODE_ALPHABET.includes(ch));
    assert.match(sessionId, /^[A-Za-z0-9_-]{43}$/);
    // the code is not a session id: polling with it (or anything else) learns nothing
    assert.equal((await ctx.call('POST', '/api/pair/status', { body: { sessionId: code } })).json.status, 'expired');
    assert.equal((await ctx.call('POST', '/api/pair/status', { body: { sessionId: 'x'.repeat(43) } })).status, 404);
    const waiting = await ctx.call('POST', '/api/pair/status', { body: { sessionId } });
    assert.equal(waiting.json.status, 'waiting');
    assert.equal(waiting.json.token, undefined);
    // claiming needs an admin session (and passes the CSRF guard)
    assert.equal((await ctx.call('POST', '/api/admin/pair/claim', { body: { code, screenId: 's_kitchen' } })).status, 401);
    assert.equal((await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code, screenId: 's_kitchen' }, headers: { origin: 'https://evil.example' } })).status, 403);
    assert.equal((await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code, screenId: 's_nope' } })).status, 400);
    const wrong = await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code: code === '222222' ? '333333' : '222222', screenId: 's_kitchen' } });
    assert.equal(wrong.status, 404);
    assert.equal(wrong.json.code, 'invalid_code');
    // lower case + separators are accepted
    const pretty = `${code.slice(0, 3)}-${code.slice(3)}`.toLowerCase();
    // step 1: only says which display is waiting; nothing is paired yet
    const ask = await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code: pretty, screenId: 's_kitchen', name: '  Hall   tablet ' } });
    assert.equal(ask.status, 200, ask.text);
    assert.equal(ask.json.device, undefined);
    assert.deepEqual(ask.json.confirm, { where: 'localhost', screenId: 's_kitchen', screenName: ask.json.confirm.screenName });
    assert.ok(ask.json.confirm.screenName);
    assert.equal((await ctx.call('POST', '/api/pair/status', { body: { sessionId } })).json.status, 'waiting');
    assert.equal((await ctx.call('GET', '/api/admin/devices', { cookie })).json.devices.length, 0);
    // step 2: confirm: true pairs
    const claim = await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code: pretty, screenId: 's_kitchen', name: '  Hall   tablet ', confirm: true } });
    assert.equal(claim.status, 200, claim.text);
    assert.equal(claim.json.device.name, 'Hall tablet');
    assert.equal(claim.json.device.screenId, 's_kitchen');
    // single use
    assert.equal((await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code, screenId: 's_main' } })).status, 404);
    const paired = await ctx.call('POST', '/api/pair/status', { body: { sessionId } });
    assert.equal(paired.json.status, 'paired');
    assert.equal(paired.json.screen.id, 's_kitchen');
    const token = paired.json.token;
    assert.match(token, DEVICE_TOKEN_RE);
    // handed out exactly once
    assert.equal((await ctx.call('POST', '/api/pair/status', { body: { sessionId } })).json.status, 'expired');
    // stored hashed only
    const secrets = fs.readFileSync(path.join(ctx.dir, 'secrets.json'), 'utf8');
    assert.ok(!secrets.includes(token));
    assert.ok(secrets.includes(claim.json.device.id));
    // the token works like a key, bound to the kitchen
    const s = await ctx.stream(`/api/stream?client=kiosk-hall&k=${encodeURIComponent(token)}`);
    assert.equal((await s.next('hello')).data.screenId, 's_kitchen');
    let devs = (await ctx.call('GET', '/api/admin/devices', { cookie })).json.devices;
    assert.equal(devs.length, 1);
    assert.ok(devs[0].lastSeenAt);
    assert.equal(devs[0].connected, true);
    assert.deepEqual(devs[0].clientIds, ['kiosk-hall']);
    assert.equal(devs[0].hash, undefined);
    assert.equal(listDisplays().find((d) => d.clientId === 'kiosk-hall').deviceName, 'Hall tablet');
    // rename
    const ren = await ctx.call('PATCH', `/api/admin/devices/${devs[0].id}`, { cookie, body: { name: 'Fridge' } });
    assert.equal(ren.json.device.name, 'Fridge');
    assert.equal((await ctx.call('PATCH', `/api/admin/devices/${devs[0].id}`, { cookie, body: { name: '   ' } })).status, 400);
    // revoke → token refused, live stream told and closed
    assert.equal((await ctx.call('DELETE', `/api/admin/devices/${devs[0].id}`, { cookie })).status, 200);
    assert.equal((await s.next('revoked')).data.code, 'invalid_key');
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': token } })).status, 403);
    devs = (await ctx.call('GET', '/api/admin/devices', { cookie })).json.devices;
    assert.equal(devs.length, 0);
    assert.equal((await ctx.call('DELETE', '/api/admin/devices/dv_nope', { cookie })).status, 404);
    const activity = fs.readFileSync(path.join(ctx.dir, 'activity.jsonl'), 'utf8');
    assert.match(activity, /display\.paired/);
    assert.match(activity, /display\.device_revoked/);
    assert.ok(!activity.includes(token) && !activity.includes(sessionId));
  });
});

const fakeDisplay = (ip = '192.168.0.50') => ({ ip, get: () => 'Chromium' });
const admin = (ip = '127.0.0.1', epoch = 'e1') => ({ ip, session: { epoch, user: { email: 'admin' } } });

test('pairing claim has two steps: the first only names the waiting display, confirm: true pairs it', async () => {
  await withServer(async () => {
    const t0 = Date.now();
    const st = startPairing(fakeDisplay('::ffff:192.168.1.77'), t0);
    const ask = claimPairing(admin(), { code: st.code, screenId: 's_kitchen', name: 'Hall' }, t0 + 100);
    assert.equal(ask.device, undefined);
    assert.equal(ask.error, undefined);
    assert.equal(ask.confirm.where, '192.168.1.77');
    assert.equal(ask.confirm.screenId, 's_kitchen');
    assert.equal(typeof ask.confirm.screenName, 'string');
    // asking again is fine, and still nothing is paired
    assert.ok(claimPairing(admin(), { code: st.code, screenId: 's_kitchen' }, t0 + 200).confirm);
    assert.equal(pairingStatus(st.sessionId, t0 + 300).status, 'waiting');
    // anything but the boolean true is only a question
    assert.ok(claimPairing(admin(), { code: st.code, screenId: 's_kitchen', confirm: 'true' }, t0 + 400).confirm);
    const done = claimPairing(admin(), { code: st.code, screenId: 's_kitchen', name: 'Hall', confirm: true }, t0 + 500);
    assert.equal(done.device.name, 'Hall');
    assert.equal(done.confirm, undefined);
    assert.equal(pairingStatus(st.sessionId, t0 + 600).status, 'paired');
    // a wrong code fails at the first step too, and counts as a wrong code
    const wrong = claimPairing(admin('127.0.0.1', 'e9'), { code: 'ZZZZZZ', screenId: 's_kitchen' }, t0 + 700);
    assert.equal(wrong.status, 404);
    assert.equal(wrong.code, 'invalid_code');
    assert.equal(displayAddress('127.0.0.1'), 'localhost');
    assert.equal(displayAddress(''), '');
  });
});

test('pairing rules: TTL, only while the display waits, single use, rate limits (per admin + global, start)', async () => {
  await withServer(async () => {
    const t0 = Date.now();
    // expiry (10 min)
    let st = startPairing(fakeDisplay(), t0);
    assert.equal(pairingStatus(st.sessionId, t0 + PAIR_TTL_MS - 1000).status, 'waiting');
    assert.equal(claimPairing(admin(), { code: st.code, screenId: 's_main' }, t0 + PAIR_TTL_MS + 1).code, 'invalid_code');
    assert.equal(pairingStatus(st.sessionId, t0 + PAIR_TTL_MS + 2).status, 'expired');
    _resetPairing();
    // display stopped polling → code no longer claimable; polling again revives it
    st = startPairing(fakeDisplay(), t0);
    assert.equal(claimPairing(admin(), { code: st.code, screenId: 's_main' }, t0 + WAITING_GRACE_MS + 1000).code, 'invalid_code');
    pairingStatus(st.sessionId, t0 + WAITING_GRACE_MS + 2000);
    assert.ok(claimPairing(admin(), { code: st.code, screenId: 's_main', confirm: true }, t0 + WAITING_GRACE_MS + 3000).device);
    assert.equal(claimPairing(admin(), { code: st.code, screenId: 's_main' }, t0 + WAITING_GRACE_MS + 3500).code, 'invalid_code', 'single use');
    _resetPairing();
    // malformed codes
    assert.equal(normalizeCode('ABC-23O'), null, 'O is not in the alphabet');
    assert.equal(normalizeCode('abc 234'), 'ABC234');
    assert.equal(normalizeCode('ABCD'), null);
    // per admin (session + address) limit: then 429 even with the right code (no oracle while locked)
    st = startPairing(fakeDisplay(), t0);
    for (let i = 0; i < CLAIM_FAIL_LIMIT; i++) assert.equal(claimPairing(admin(), { code: 'ZZZZZZ', screenId: 's_main' }, t0).status, 404);
    assert.equal(claimPairing(admin(), { code: st.code, screenId: 's_main' }, t0).status, 429);
    // another admin session is not blocked by it…
    assert.ok(claimPairing(admin('127.0.0.1', 'e2'), { code: st.code, screenId: 's_main', confirm: true }, t0).device);
    // …and the window passes
    _resetPairing();
    // global limit across sessions / addresses
    st = startPairing(fakeDisplay(), t0);
    for (let i = 0; i < CLAIM_FAIL_GLOBAL; i++) claimPairing(admin(`10.0.${i}.1`, `g${i}`), { code: 'ZZZZZZ', screenId: 's_main' }, t0);
    assert.equal(claimPairing(admin('10.9.9.9', 'fresh'), { code: st.code, screenId: 's_main' }, t0).status, 429);
    _resetPairing();
    // starting codes: per address limit, unique codes
    const codes = new Set();
    for (let i = 0; i < START_LIMIT; i++) codes.add(startPairing(fakeDisplay('192.168.1.77'), t0).code);
    assert.equal(codes.size, START_LIMIT);
    assert.equal(startPairing(fakeDisplay('192.168.1.77'), t0).status, 429);
    assert.ok(startPairing(fakeDisplay('192.168.1.78'), t0).code);
    // an address keeps at most MAX_PENDING_PER_ADDRESS codes waiting: a newer one replaces its oldest
    assert.equal(_pendingCount(), MAX_PENDING_PER_ADDRESS + 1);
    _resetPairing();
  });
});

test('pairing start is rate-limited over HTTP too', async () => {
  await withServer(async (ctx) => {
    for (let i = 0; i < START_LIMIT; i++) assert.equal((await ctx.call('POST', '/api/pair/start', { body: {} })).status, 200);
    const r = await ctx.call('POST', '/api/pair/start', { body: {} });
    assert.equal(r.status, 429);
    assert.ok(r.headers.get('retry-after'));
  });
});

test('redaction: keys, device tokens and pairing ids never reach logs', async () => {
  const key = '2f1c29f3-0c34-4e29-a6ac-ea4627b72883';
  const tok = `md_${'x'.repeat(43)}`;
  assert.equal(redactSecrets(`/d/${key}?client=pi`), '/d/[redacted]?client=pi');
  assert.equal(redactSecrets(`/api/stream?client=a&k=${key}&x=1`), '/api/stream?client=a&k=[redacted]&x=1');
  assert.equal(redactSecrets(`token ${tok} used`), 'token md_[redacted] used');
  assert.equal(redactSecrets('/api/events?from=2026-01-01'), '/api/events?from=2026-01-01');
  await withServer(async () => {
    logActivity('test.redaction', { actor: 'system', data: { url: `/d/${key}`, token: tok, nested: { u: `/media/photos/a.jpg?k=${key}` } } });
    const e = listActivity({ type: 'test' }).items[0];
    const s = JSON.stringify(e);
    assert.ok(!s.includes(key) && !s.includes(tok), s);
    assert.match(s, /\[redacted\]/);
  });
  // server error log lines (5xx) carry the redacted URL
  const src = fs.readFileSync(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(src, /console\.error\('\[server\]', req\.method, redactSecrets\(req\.originalUrl\)/);
});

test('migration: existing configs keep working (open), fresh installs are private, saves keep the mode', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marco-access-mig-'));
  try {
    // fresh install: no config file → private
    store.initStore(dir);
    assert.equal(store.getConfig().security.displayAccess, 'private');
    assert.equal(store.migratedOnLoad, null);
    // existing v2 config from 0.2 (no `security`) → open, persisted, reported
    const old = defaultConfig();
    delete old.security;
    old.revision = 7;
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(old));
    store.initStore(dir);
    assert.equal(store.getConfig().security.displayAccess, 'open');
    assert.equal(store.migratedOnLoad.displayAccess, 'open');
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'config.json'), 'utf8')).security.displayAccess, 'open');
    // reload: already migrated, nothing reported
    store.initStore(dir);
    assert.equal(store.getConfig().security.displayAccess, 'open');
    assert.equal(store.migratedOnLoad, null);
    // a save without `security` (old admin build, old backup / export) keeps the current mode…
    const noSec = structuredClone(store.getConfig());
    delete noSec.security;
    assert.ok(store.saveConfig(noSec, { backup: false }).ok);
    assert.equal(store.getConfig().security.displayAccess, 'open');
    // …an explicit one changes it; invalid values are refused
    assert.ok(store.saveConfig({ ...noSec, security: { displayAccess: 'private' } }, { backup: false }).ok);
    assert.equal(store.getConfig().security.displayAccess, 'private');
    assert.ok(store.saveConfig(noSec, { backup: false }).ok);
    assert.equal(store.getConfig().security.displayAccess, 'private');
    assert.equal(store.saveConfig({ ...noSec, security: { displayAccess: 'public' } }, { backup: false }).ok, false);
    // v1 (single-screen) configs are old by definition → open
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ version: 1, screen: { name: 'Salón' }, calendar: { sources: [] } }));
    store.initStore(dir);
    assert.equal(store.getConfig().security.displayAccess, 'open');
    assert.equal(store.migratedOnLoad.from, 1);
    assert.equal(store.migratedOnLoad.displayAccess, 'open');
    // every screen gets a UUIDv4 key in secrets.json (0600)
    syncDisplayKeys();
    const sec = JSON.parse(fs.readFileSync(path.join(dir, 'secrets.json'), 'utf8'));
    for (const s of store.getConfig().screens) assert.match(sec.displayKeys[s.id].key, KEY_RE);
    if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(dir, 'secrets.json')).mode & 0o777, 0o600);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('export with secrets → import on another install keeps private links and paired devices', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const key = keyOf('kitchen');
    const st = startPairing(fakeDisplay(), Date.now());
    claimPairing(admin(), { code: st.code, screenId: 's_kitchen', name: 'Hall tablet', confirm: true });
    const token = pairingStatus(st.sessionId).token;
    const plain = (await ctx.call('POST', '/api/admin/export', { cookie, body: { includeSecrets: false } })).json;
    assert.ok(!JSON.stringify(plain).includes(key), 'keys only travel in exports that include secrets');
    const bundle = (await ctx.call('POST', '/api/admin/export', { cookie, body: { includeSecrets: true } })).json;
    assert.equal(bundle.secrets.displayKeys.s_kitchen.key, key);
    assert.ok(!JSON.stringify(bundle).includes(token), 'device tokens are exported as hashes only');
    // "another install": new keys, no devices
    await ctx.call('POST', '/api/admin/display-links/s_kitchen/regenerate', { cookie, body: {} });
    await ctx.call('DELETE', `/api/admin/devices/${bundle.secrets.devices[0].id}`, { cookie });
    assert.equal((await ctx.call('GET', '/api/events', { headers: { 'x-marco-key': key } })).status, 403);
    const ap = await ctx.call('POST', '/api/admin/import/apply', { cookie, body: { bundle, includeSecrets: true } });
    assert.equal(ap.status, 200, ap.text);
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': key } })).json.screenId, 's_kitchen');
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { 'x-marco-key': token } })).json.screenId, 's_kitchen');
  });
});

// ------------------------------------------------------------------------------------------------------------------
// Review fixes: live streams follow every credential change (no path leaves a stream reading after revocation).

/** Wait until the stream has ended (server closed it). */
const ended = async (s, ms = 2000) => {
  const t0 = Date.now();
  while (!s.ended()) {
    if (Date.now() - t0 > ms) throw new Error('stream still open');
    await new Promise((r) => setTimeout(r, 20));
  }
};
/** Pair a device to `screenId` and return its token. */
const pairDevice = (screenId, name = 'Tablet') => {
  const st = startPairing(fakeDisplay(), Date.now());
  const c = claimPairing(admin(), { code: st.code, screenId, name, confirm: true });
  assert.ok(c.device, JSON.stringify(c));
  return { token: pairingStatus(st.sessionId).token, id: c.device.id };
};

test('open → private with a connected kiosk and a config broadcast in the same tick: server stays up', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const kiosk = await ctx.stream('/api/stream?client=kiosk-living');
    await kiosk.next('hello');
    let crashed = null;
    const onErr = (err) => { crashed = err; };
    process.on('uncaughtException', onErr);
    try {
      const cfg = (await ctx.call('GET', '/api/admin/config', { cookie })).json;
      cfg.security.displayAccess = 'private';
      assert.equal((await ctx.call('PUT', '/api/admin/config', { cookie, body: cfg })).status, 200);
      assert.equal((await kiosk.next('revoked')).data.code, 'key_required');
      await ended(kiosk);
      // a screen with a connected private-link display is deleted (kick 'invalid_key' + broadcast)
      const keyed = await ctx.stream(`/api/stream?client=kiosk-k&k=${keyOf('kitchen')}`);
      await keyed.next('hello');
      const cfg2 = (await ctx.call('GET', '/api/admin/config', { cookie })).json;
      cfg2.screens = cfg2.screens.filter((x) => x.id !== 's_kitchen');
      assert.equal((await ctx.call('PUT', '/api/admin/config', { cookie, body: cfg2 })).status, 200);
      assert.equal((await keyed.next('revoked')).data.code, 'invalid_key');
      await ended(keyed);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(crashed, null, String(crashed?.stack));
      // nothing ended is left in the registry; the server still answers
      assert.ok(listClients().every((c) => !c.res.writableEnded));
      assert.equal((await ctx.call('GET', '/api/admin/config', { cookie })).status, 200);
    } finally {
      process.off('uncaughtException', onErr);
    }
  }, { mode: 'open' });
});

test('import with secrets: replaced keys and dropped devices close their live streams; untouched ones stay', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const bundle = (await ctx.call('POST', '/api/admin/export', { cookie, body: { includeSecrets: true } })).json;
    const { token } = pairDevice('s_kitchen', 'Tab2');
    const oldKitchen = keyOf('kitchen');
    // the bundle gets a different kitchen key; the main key is the same as now; the new device is not in it
    bundle.secrets.displayKeys.s_kitchen.key = '0b6c1f9e-3d2a-4c8b-9e7f-1a2b3c4d5e6f';
    const kitchen = await ctx.stream(`/api/stream?client=k1&k=${oldKitchen}`);
    const main = await ctx.stream(`/api/stream?client=m1&k=${keyOf('living-room')}`);
    const dev = await ctx.stream(`/api/stream?client=t1&k=${encodeURIComponent(token)}`);
    for (const s of [kitchen, main, dev]) await s.next('hello');
    const pv = (await ctx.call('POST', '/api/admin/import/preview', { cookie, body: { bundle } })).json;
    assert.deepEqual(pv.secretsImpact.linksChanged, ['Kitchen']);
    assert.deepEqual(pv.secretsImpact.devicesRemoved, ['Tab2']);
    const ap = await ctx.call('POST', '/api/admin/import/apply', { cookie, body: { bundle, includeSecrets: true } });
    assert.equal(ap.status, 200, ap.text);
    assert.equal((await kitchen.next('revoked')).data.code, 'invalid_key');
    assert.equal((await dev.next('revoked')).data.code, 'invalid_key');
    await ended(kitchen);
    await ended(dev);
    // later broadcasts never reach them; the main-screen stream (same key) stays
    broadcast('announce', { id: 'after-import', text: 'AFTER IMPORT secret' });
    await main.next('announce');
    assert.ok(!kitchen.events().some((e) => e.event === 'announce'));
    assert.ok(!dev.events().some((e) => e.event === 'announce'));
    assert.ok(!main.ended());
    assert.equal((await ctx.call('GET', '/api/admin/devices', { cookie })).json.devices.length, 0);
    main.close();
  });
});

test('admin-session streams close on logout-all, password change and plain logout of the same browser', async () => {
  await withServer(async (ctx) => {
    // logout-all
    let cookie = await ctx.login();
    let s = await ctx.stream('/api/stream?screen=kitchen', { cookie });
    await s.next('hello');
    assert.equal((await ctx.call('POST', '/api/auth/logout-all', { cookie, body: {} })).status, 200);
    assert.equal((await s.next('revoked')).data.code, 'key_required');
    await ended(s);
    assert.equal(broadcast('announce', { id: 'a1', text: 'SECRET family message' }), 0);
    // password change: other sessions' streams close, the browser that changed it keeps working with a new cookie
    cookie = await ctx.login();
    const other = await ctx.login();
    s = await ctx.stream('/api/stream?screen=kitchen', { cookie: other });
    await s.next('hello');
    const pw = await ctx.call('PUT', '/api/admin/password', { cookie, body: { current: 'secret-pass-123', next: 'another-pass-456' } });
    assert.equal(pw.status, 200, pw.text);
    assert.equal((await s.next('revoked')).data.code, 'key_required');
    await ended(s);
    // plain logout closes the streams opened by that login only
    const a = await ctx.call('POST', '/api/auth/login', { body: { password: 'another-pass-456' } });
    const b = await ctx.call('POST', '/api/auth/login', { body: { password: 'another-pass-456' } });
    const ca = a.setCookie.map((x) => x.split(';')[0]).join('; ');
    const cb = b.setCookie.map((x) => x.split(';')[0]).join('; ');
    const sa = await ctx.stream('/api/stream?screen=kitchen&preview=1', { cookie: ca });
    const sb = await ctx.stream('/api/stream?screen=kitchen&preview=1', { cookie: cb });
    await sa.next('hello');
    await sb.next('hello');
    assert.equal((await ctx.call('POST', '/api/auth/logout', { cookie: ca, body: {} })).status, 200);
    assert.equal((await sa.next('revoked')).data.code, 'key_required');
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(!sb.ended());
    // disabling the login method (config) also closes them
    const cfg = (await ctx.call('GET', '/api/admin/config', { cookie: cb })).json;
    store.updateConfig((c) => { c.auth.passwordLoginEnabled = false; c.auth.allowedGoogleEmails = ['x@example.com']; });
    assert.equal((await sb.next('revoked')).data.code, 'key_required');
    assert.ok(cfg);
  });
});

test('moving a paired device to another screen closes its stream; it never gets the old screen\'s events', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const { token, id } = pairDevice('s_kitchen');
    const s = await ctx.stream(`/api/stream?client=tab-1&k=${encodeURIComponent(token)}`);
    assert.equal((await s.next('hello')).data.screenId, 's_kitchen');
    const r = await ctx.call('PATCH', `/api/admin/devices/${id}`, { cookie, body: { screenId: 's_main' } });
    assert.equal(r.status, 200, r.text);
    await s.next('reload');
    await ended(s);
    assert.equal(broadcast('announce', { id: 'k', text: 'kitchen only' }, { screenIds: ['s_kitchen'] }), 0);
    // reconnecting follows the new binding
    const s2 = await ctx.stream(`/api/stream?client=tab-1&k=${encodeURIComponent(token)}`);
    assert.equal((await s2.next('hello')).data.screenId, 's_main');
    s2.close();
  });
});

test('revalidateStreams: every credential is re-checked against the current secrets', async () => {
  await withServer(async (ctx) => {
    const s = await ctx.stream(`/api/stream?client=k9&k=${keyOf('kitchen')}`);
    await s.next('hello');
    assert.equal(revalidateStreams(), 0);
    // a key swapped behind the API's back (e.g. a restored secrets.json) is caught by the next check
    store.updateSecrets((x) => { x.displayKeys.s_kitchen.key = '0b6c1f9e-3d2a-4c8b-9e7f-1a2b3c4d5e6f'; });
    assert.equal(revalidateStreams(), 1);
    assert.equal((await s.next('revoked')).data.code, 'invalid_key');
  });
});

test('restore and import keep the current display access mode (both directions); preview says so', async () => {
  for (const [mode, other] of [['open', 'private'], ['private', 'open']]) {
    await withServer(async (ctx) => {
      const cookie = await ctx.login();
      const bundle = (await ctx.call('POST', '/api/admin/export', { cookie, body: { includeSecrets: false } })).json;
      // a bundle with the other mode, and one without any security section (pre-0.3)
      const withOther = structuredClone(bundle);
      withOther.config.security = { displayAccess: other };
      const legacy = structuredClone(bundle);
      delete legacy.config.security;
      for (const b of [withOther, legacy]) {
        const pv = (await ctx.call('POST', '/api/admin/import/preview', { cookie, body: { bundle: b } })).json;
        assert.equal(pv.displayAccess, mode);
        assert.equal((await ctx.call('POST', '/api/admin/import/apply', { cookie, body: { bundle: b, includeSecrets: false } })).status, 200);
        assert.equal(store.getConfig().security.displayAccess, mode);
      }
      // restore of a backup written in the other mode
      const backupDir = path.join(ctx.dir, 'backups');
      const cfg = structuredClone(store.getConfig());
      cfg.security = { displayAccess: other };
      fs.writeFileSync(path.join(backupDir, 'config-20240101T000000Z-r1-manual.json'), JSON.stringify(cfg));
      const list = (await ctx.call('GET', '/api/admin/backups', { cookie })).json;
      const id = (list.backups || list).find((x) => x.id.includes('20240101')).id;
      const r = await ctx.call('POST', `/api/admin/backups/${id}/restore`, { cookie, body: {} });
      assert.equal(r.status, 200, r.text);
      assert.equal(store.getConfig().security.displayAccess, mode);
      assert.equal((await ctx.call('GET', '/api/display/config')).status, mode === 'open' ? 200 : 401);
    }, { mode });
  }
});

test('display-links tells an admin on localhost how other devices reach the server (LAN address / PUBLIC_URL)', async () => {
  const prev = { lan: process.env.LAN_ADDRESS, pub: process.env.PUBLIC_URL };
  process.env.LAN_ADDRESS = '10.0.0.7';
  process.env.PUBLIC_URL = 'http://localhost:3000';
  try {
    await withServer(async (ctx) => {
      const cookie = await ctx.login();
      let r = (await ctx.call('GET', '/api/admin/display-links', { cookie })).json;
      assert.deepEqual(r.lanAddresses, ['10.0.0.7']);
      assert.equal(r.publicUrl, null, 'a localhost PUBLIC_URL is no use to other devices');
      process.env.PUBLIC_URL = 'https://calendar.example.com/';
      r = (await ctx.call('GET', '/api/admin/display-links', { cookie })).json;
      assert.equal(r.publicUrl, 'https://calendar.example.com');
    });
  } finally {
    for (const [k, v] of [['LAN_ADDRESS', prev.lan], ['PUBLIC_URL', prev.pub]]) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
});
test('browser headers: no referrer, nosniff, same-origin framing only, display and admin pages never cached', async () => {
  await withServer(async (ctx) => {
    for (const url of ['/', '/index.html', '/?screen=salon', '/pair', '/admin/', '/admin/index.html', '/api/health', `/d/${keyOf('kitchen')}`]) {
      const r = await ctx.call('GET', url);
      assert.equal(r.status, 200, url);
      assert.equal(r.headers.get('referrer-policy'), 'no-referrer', url);
      assert.equal(r.headers.get('x-content-type-options'), 'nosniff', url);
      assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN', url);
      assert.match(r.headers.get('content-security-policy'), /frame-ancestors 'self'/, url);
      if (url !== '/api/health') assert.match(r.headers.get('cache-control'), /no-store/, url);
    }
  });
});

test('EMBED_ORIGINS: only the display page may be framed by the listed origins; unset keeps same-origin framing', async () => {
  const prev = process.env.EMBED_ORIGINS;
  try {
    await withServer(async (ctx) => {
      const framed = { 'sec-fetch-dest': 'iframe', 'sec-fetch-site': 'same-site' };
      const display = `/d/${keyOf('kitchen')}`;
      delete process.env.EMBED_ORIGINS;
      let r = await ctx.call('GET', display, { headers: framed });
      assert.equal(r.status, 403, 'unset: a cross-site framed load is refused');
      process.env.EMBED_ORIGINS = 'http://192.168.0.27:8080/, javascript:alert(1), http://x.test; script-src *';
      r = await ctx.call('GET', display, { headers: framed });
      assert.equal(r.status, 200);
      assert.equal(r.headers.get('x-frame-options'), null);
      assert.equal(r.headers.get('content-security-policy'), "frame-ancestors 'self' http://192.168.0.27:8080");
      r = await ctx.call('HEAD', display, { headers: framed });
      assert.equal(r.status, 200, 'HEAD gets the same headers as GET');
      assert.equal(r.headers.get('x-frame-options'), null);
      assert.equal(r.headers.get('content-security-policy'), "frame-ancestors 'self' http://192.168.0.27:8080");
      for (const url of ['/admin/', '/admin/index.html', '/api/health', '/pair']) {
        r = await ctx.call('GET', url, { headers: framed });
        assert.equal(r.status, 403, `${url} is never frameable by an embed origin`);
        r = await ctx.call('GET', url);
        assert.equal(r.headers.get('x-frame-options'), 'SAMEORIGIN', url);
        assert.equal(r.headers.get('content-security-policy'), "frame-ancestors 'self'", url);
      }
    });
  } finally {
    if (prev === undefined) delete process.env.EMBED_ORIGINS; else process.env.EMBED_ORIGINS = prev;
  }
});

test('admin CSRF: same-origin only, by Origin and Sec-Fetch-Site; works on the LAN address and through an SSH tunnel', async () => {
  const http = await import('node:http');
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const { port } = new URL(ctx.base);
    // Raw request so the Host header can be what the browser sent (LAN IP, or localhost through a tunnel).
    const post = (headers) => new Promise((resolve, reject) => {
      const body = '{}';
      const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/admin/backups',
        headers: { cookie, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers } }, (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      });
      req.on('error', reject);
      req.end(body);
    });
    assert.equal(await post({ host: '192.168.0.50:3100', origin: 'http://192.168.0.50:3100' }), 200);
    assert.equal(await post({ host: 'localhost:3100', origin: 'http://localhost:3100', 'sec-fetch-site': 'same-origin' }), 200);
    assert.equal(await post({ host: '192.168.0.50:3100' }), 200, 'no Origin (old clients, curl) still works');
    assert.equal(await post({ host: 'localhost:3100', origin: 'http://localhost:3100', 'sec-fetch-site': 'cross-site' }), 403);
    assert.equal(await post({ host: 'localhost:3100', origin: 'http://localhost:3100', 'sec-fetch-site': 'same-site' }), 403);
    assert.equal(await post({ host: 'localhost:3100', 'sec-fetch-site': 'cross-site' }), 403, 'Sec-Fetch-Site alone refuses');
    assert.equal(await post({ host: '192.168.0.50:3100', origin: 'http://evil.example' }), 403);
    assert.equal(await post({ host: '192.168.0.50:3100', origin: 'http://192.168.0.50:3101' }), 403, 'another port is another origin');
    // the display's own POSTs (no admin cookie) are outside the guard
    assert.notEqual((await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-x' }, headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  }, { mode: 'open' });
});

// ---------------------------------------------------------------------------------------------------------------
// Unknown ?screen=: 404 screen_not_found everywhere, never the default screen's data (docs/API.md)

const withScreen = (url, s) => `${url}${url.includes('?') ? '&' : '?'}screen=${encodeURIComponent(s)}`;
const NOT_FOUND_ENDPOINTS = [
  ...ENDPOINTS.filter((ep) => !ep.sse),
  { name: 'doorbell frame', method: 'GET', url: '/api/display/doorbell/frame' },
];

/** { status, json } of one endpoint for ?screen=<s>. */
async function hitScreen(ctx, ep, s, opts = {}) {
  const r = await ctx.call(ep.method, withScreen(ep.url, s), { body: ep.body, ...opts });
  return { status: r.status, json: r.json };
}

test('unknown ?screen= (open mode, admin session): every display endpoint answers 404 screen_not_found', async () => {
  for (const mode of ['open', 'private']) {
    await withServer(async (ctx) => {
      const opts = mode === 'private' ? { cookie: await ctx.login() } : {};
      for (const s of ['nope', 'NOPE', 's_nope', 'v_nope']) {
        for (const ep of NOT_FOUND_ENDPOINTS) {
          const r = await hitScreen(ctx, ep, s, opts);
          assert.equal(r.status, 404, `${mode} ${ep.name} ?screen=${s}`);
          assert.equal(r.json?.error, 'screen_not_found', `${mode} ${ep.name} ?screen=${s}`);
          // nothing about the screens that exist
          assert.deepEqual(Object.keys(r.json).sort(), ['code', 'error'], `${mode} ${ep.name}: no data`);
        }
      }
      // ?screen=a&screen=b names no single screen
      assert.equal((await ctx.call('GET', '/api/display/config?screen=kitchen&screen=main', opts)).json.error, 'screen_not_found');
      // the stream is refused before it opens: not registered, no live events
      const s = await ctx.stream('/api/stream?screen=nope&client=kiosk-ghost', opts);
      assert.equal(s.status, 404);
      assert.equal(listClients().length, 0);
      assert.ok(!listDisplays().some((d) => d.clientId === 'kiosk-ghost'));
      // a poll that is refused does not register a display either
      assert.equal((await ctx.call('GET', '/api/display/poll?client=kiosk-ghost2&screen=nope', opts)).status, 404);
      assert.ok(!listDisplays().some((d) => d.clientId === 'kiosk-ghost2'));
    }, { mode });
  }
});

test('no ?screen= (or an empty one) from this machine is still the default screen; known screens and carousels resolve as before', async () => {
  await withServer(async (ctx) => {
    for (const url of ['/api/display/config', '/api/display/config?screen=', '/api/display/config?screen=%20']) {
      const r = await ctx.call('GET', url);
      assert.equal(r.status, 200, url);
      assert.equal(r.json.screenId, 's_main', url);
    }
    assert.equal((await ctx.call('GET', '/api/display/config?screen=KITCHEN')).json.screenId, 's_kitchen');
    assert.equal((await ctx.call('GET', '/api/display/config?screen=s_kitchen')).json.screenId, 's_kitchen');
    for (const ep of ENDPOINTS.filter((e) => !e.sse)) {
      assert.ok(allowed(ep, await hit(ctx, ep)), `${ep.name}: no ?screen=`);
      assert.ok(allowed(ep, (await hitScreen(ctx, ep, 'kitchen')).status), `${ep.name}: ?screen=kitchen`);
    }
    const s = await ctx.stream('/api/stream?client=kiosk-default');
    assert.equal(s.status, 200);
    assert.equal((await s.next('hello')).data.screenId, 's_main');
    s.close();
  }, { mode: 'open' });
});

test('unknown ?screen= with a credential: its bound screen wins as before', async () => {
  await withServer(async (ctx) => {
    const kitchenKey = keyOf('kitchen');
    const r = await ctx.call('GET', '/api/display/config?screen=nope', { headers: { 'x-marco-key': kitchenKey } });
    assert.equal(r.status, 200);
    assert.equal(r.json.screenId, 's_kitchen');
    const s = await ctx.stream(`/api/stream?screen=nope&client=kiosk-k&k=${kitchenKey}`);
    assert.equal(s.status, 200);
    assert.equal((await s.next('hello')).data.screenId, 's_kitchen');
    s.close();
  });
});

test('heartbeat for an unknown screen: 404, not listed, never under the default screen', async () => {
  await withServer(async (ctx) => {
    const r = await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-hb', screen: 'nope' } });
    assert.equal(r.status, 404);
    assert.equal(r.json.error, 'screen_not_found');
    assert.ok(!listDisplays().some((d) => d.clientId === 'kiosk-hb'));
    assert.equal((await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-hb', screen: 'kitchen' } })).status, 200);
    assert.equal(listDisplays().find((d) => d.clientId === 'kiosk-hb').screenId, 's_kitchen');
  }, { mode: 'open' });
});

// ---------------------------------------------------------------------------------------------------------------
// The bare address (no ?screen=, no credential): open mode shows no screen to other machines; the server itself
// (all-in-one kiosk on http://localhost) keeps the default screen. A LAN client is simulated with a reverse proxy on
// this machine (trusted by default) passing X-Forwarded-For.

const LAN = { 'x-forwarded-for': '192.168.0.50' };
const BARE_ENDPOINTS = [
  ...ENDPOINTS.filter((ep) => !ep.sse && !ep.url.startsWith('/media/') && ep.name !== 'news' && ep.name !== 'heartbeat'),
  { name: 'doorbell frame', method: 'GET', url: '/api/display/doorbell/frame' },
];

test('bare address from the LAN (open mode): 404 screen_not_found on every per-screen endpoint, no data', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    for (const opts of [{ headers: LAN }, { headers: LAN, cookie }]) {
      for (const ep of BARE_ENDPOINTS) {
        for (const suffix of ['', ep.url.includes('?') ? '&screen=' : '?screen=', ep.url.includes('?') ? '&screen=%20' : '?screen=%20']) {
          const r = await ctx.call(ep.method, ep.url + suffix, { body: ep.body, ...opts });
          const what = `${ep.name}${suffix}${opts.cookie ? ' (session)' : ''}`;
          assert.equal(r.status, 404, what);
          assert.deepEqual(r.json, { error: 'screen_not_found', code: 'screen_not_found' }, what);
        }
      }
      // a screen named in the URL works from the LAN as before
      assert.equal((await ctx.call('GET', '/api/display/config?screen=kitchen', opts)).json.screenId, 's_kitchen');
      assert.equal((await ctx.call('GET', '/api/display/config?screen=living-room', opts)).json.screenId, 's_main');
    }
    // not about one screen: news, gallery files (their URLs come from /api/photos, which needs a screen)
    assert.equal((await ctx.call('GET', '/api/news', { headers: LAN })).status, 200);
    assert.equal((await ctx.call('GET', '/media/photos/family.jpg', { headers: LAN })).status, 200);
    // nor the electricity prices of a zone: a TV or the admin's widget preview on the LAN asks with no screen (a
    // known zone answers 200 or 502 from its source, never 404 screen_not_found)
    const pr = await ctx.call('GET', '/api/display/prices?zone=no-such-zone', { headers: LAN });
    assert.equal(pr.status, 400);
    assert.equal(pr.json.error, 'invalid_zone');
    // the stream is refused before it opens: not registered
    const s = await ctx.stream('/api/stream?client=kiosk-bare-lan', { headers: LAN });
    assert.equal(s.status, 404);
    assert.equal(listClients().length, 0);
    // a heartbeat naming no screen is not listed (and never under the default screen)
    const hb = await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-bare-lan' }, headers: LAN });
    assert.equal(hb.status, 404);
    assert.equal(hb.json.error, 'screen_not_found');
    assert.ok(!listDisplays().some((d) => d.clientId === 'kiosk-bare-lan'));
    assert.equal((await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-bare-lan', screen: 'kitchen' }, headers: LAN })).status, 200);
  }, { mode: 'open' });
});

test('bare address from this machine (all-in-one kiosk): the default screen as before', async () => {
  await withServer(async (ctx) => {
    for (const headers of [{}, { 'x-forwarded-for': '127.0.0.1' }, { 'x-forwarded-for': '::1' }]) {
      const r = await ctx.call('GET', '/api/display/config', { headers });
      assert.equal(r.status, 200);
      assert.equal(r.json.screenId, 's_main');
    }
    for (const ep of ENDPOINTS.filter((e) => !e.sse)) assert.ok(allowed(ep, await hit(ctx, ep)), `${ep.name}: bare from localhost`);
    // no ring now: 404 no_ring, not screen_not_found
    assert.equal((await ctx.call('GET', '/api/display/doorbell/frame')).json.code, 'no_ring');
    const s = await ctx.stream('/api/stream?client=kiosk-local');
    assert.equal(s.status, 200);
    assert.equal((await s.next('hello')).data.screenId, 's_main');
    s.close();
    assert.equal((await ctx.call('POST', '/api/display/heartbeat', { body: { clientId: 'kiosk-local-hb' } })).status, 200);
    assert.equal(listDisplays().find((d) => d.clientId === 'kiosk-local-hb').screenId, 's_main');
  }, { mode: 'open' });
});

test('bare address with a key or a paired device from the LAN: its bound screen', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const st = await ctx.call('POST', '/api/pair/start', { body: {} });
    await ctx.call('POST', '/api/admin/pair/claim', { cookie, body: { code: st.json.code, screenId: 's_kitchen', name: 'Hall tablet', confirm: true } });
    const deviceToken = (await ctx.call('POST', '/api/pair/status', { body: { sessionId: st.json.sessionId } })).json.token;
    assert.match(deviceToken, DEVICE_TOKEN_RE);
    for (const cred of [keyOf('kitchen'), deviceToken]) {
      const r = await ctx.call('GET', '/api/display/config', { headers: { ...LAN, 'x-marco-key': cred } });
      assert.equal(r.status, 200);
      assert.equal(r.json.screenId, 's_kitchen');
      for (const ep of ENDPOINTS.filter((e) => !e.sse)) assert.ok(allowed(ep, await hit(ctx, ep, { cred, headers: LAN })), `${ep.name}: bare + credential`);
      assert.equal((await ctx.call('GET', '/api/display/doorbell/frame', { headers: { ...LAN, 'x-marco-key': cred } })).json.code, 'no_ring');
    }
    const s = await ctx.stream(`/api/stream?client=kiosk-k-lan&k=${keyOf('living-room')}`, { headers: LAN });
    assert.equal(s.status, 200);
    assert.equal((await s.next('hello')).data.screenId, 's_main');
    s.close();
  }, { mode: 'open' });
});

test('private mode is unchanged: no credential is 401, an admin session from the LAN still gets the default screen', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: LAN })).status, 401);
    const r = await ctx.call('GET', '/api/display/config', { headers: LAN, cookie });
    assert.equal(r.status, 200);
    assert.equal(r.json.screenId, 's_main');
    assert.equal((await ctx.call('GET', '/api/display/config', { headers: { ...LAN, 'x-marco-key': keyOf('kitchen') } })).json.screenId, 's_kitchen');
  }, { mode: 'private' });
});

test('private → open: a bare admin-session stream from the LAN reloads (no default screen); localhost stays', async () => {
  await withServer(async (ctx) => {
    const cookie = await ctx.login();
    const lan = await ctx.stream('/api/stream?client=kiosk-sess-lan', { headers: LAN, cookie });
    const local = await ctx.stream('/api/stream?client=kiosk-sess-local', { cookie });
    const named = await ctx.stream('/api/stream?client=kiosk-sess-named&screen=kitchen', { headers: LAN, cookie });
    for (const x of [lan, local, named]) await x.next('hello');
    const cfg = (await ctx.call('GET', '/api/admin/config', { cookie })).json;
    cfg.security.displayAccess = 'open';
    assert.equal((await ctx.call('PUT', '/api/admin/config', { cookie, body: cfg })).status, 200);
    await lan.next('reload');
    await new Promise((r) => setTimeout(r, 100));
    assert.ok(!local.events().some((e) => e.event === 'reload' || e.event === 'revoked'));
    assert.ok(!named.events().some((e) => e.event === 'reload' || e.event === 'revoked'));
    local.close();
    named.close();
  }, { mode: 'private' });
});

test('isLoopbackClient: only this machine, never a spoofed or untrusted forwarded address', () => {
  const trustLoopback = (addr) => addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
  const req = (ip, peer, headers = {}) => ({ ip, headers, socket: { remoteAddress: peer }, app: { get: () => trustLoopback } });
  assert.equal(isLoopbackClient(req('127.0.0.1', '127.0.0.1')), true);
  assert.equal(isLoopbackClient(req('::1', '::1')), true);
  assert.equal(isLoopbackClient(req('::ffff:127.0.0.1', '::ffff:127.0.0.1')), true);
  assert.equal(isLoopbackClient(req('192.168.0.50', '192.168.0.50')), false);
  // a proxy on this machine passing the LAN client: req.ip is the client
  assert.equal(isLoopbackClient(req('192.168.0.50', '127.0.0.1', { 'x-forwarded-for': '192.168.0.50' })), false);
  // a LAN client claiming X-Forwarded-For: 127.0.0.1 (not trusted: req.ip stays its own address)
  assert.equal(isLoopbackClient(req('192.168.0.50', '192.168.0.50', { 'x-forwarded-for': '127.0.0.1' })), false);
  // TRUST_PROXY points elsewhere and a proxy on this machine forwards: not trusted, never local
  const other = { ip: '127.0.0.1', headers: { 'x-forwarded-for': '203.0.113.9' }, socket: { remoteAddress: '127.0.0.1' }, app: { get: () => () => false } };
  assert.equal(isLoopbackClient(other), false);
});
