// FURA SYSTEM — server API (Netlify Function). Barcha ruxsat tekshiruvlari shu yerda.
// Muhit o'zgaruvchilari: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET (32+ belgi),
// OWNER_HASH_1, OWNER_HASH_2 (tools/owner-hash.html bergan "pbkdf2$..." qatorlari).
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

let _db = null;
export function __setDb(d) { _db = d; }
function db() {
  if (_db) return _db;
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return null;
  _db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
  return _db;
}
const secret = () => process.env.SESSION_SECRET || '';
const dataKey = () => { const k = process.env.DATA_KEY || ''; return /^[0-9a-fA-F]{64}$/.test(k) ? Buffer.from(k, 'hex') : null; };
const configured = () => !!db() && secret().length >= 32 && !!dataKey();
// Ma'lumotlar serverda AES-256-GCM bilan shifrlanib saqlanadi (kalit: DATA_KEY). AAD = mashina_id:kalit
function encVal(vid, key, value) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', dataKey(), iv);
  c.setAAD(Buffer.from(`${vid}:${key}`));
  const ct = Buffer.concat([c.update(String(value), 'utf8'), c.final()]);
  return 'sv1:' + iv.toString('base64') + '.' + ct.toString('base64') + '.' + c.getAuthTag().toString('base64');
}
function decVal(vid, key, blob) {
  if (typeof blob !== 'string' || !blob.startsWith('sv1:')) return blob;
  try {
    const [iv, ct, tag] = blob.slice(4).split('.').map((x) => Buffer.from(x, 'base64'));
    const d = crypto.createDecipheriv('aes-256-gcm', dataKey(), iv);
    d.setAAD(Buffer.from(`${vid}:${key}`)); d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch { return null; }
}

const HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff'
};
const out = (statusCode, body) => ({ statusCode, headers: HEADERS, body: JSON.stringify(body) });
class HttpError extends Error { constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; } }
const fail = (status, message, extra) => { throw new HttpError(status, message, extra); };

// ---------- tokenlar (HMAC-SHA256) ----------
function sign(payload, ttlSec) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSec })).toString('base64url');
  const sig = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(token, role) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (!p || !p.exp || p.exp < Date.now() / 1000 || (role && p.r !== role)) return null;
  return p;
}
function need(event, role) {
  const h = event.headers || {};
  const raw = h.authorization || h.Authorization || '';
  const p = verifyToken(raw.replace(/^Bearer\s+/i, ''), role);
  if (!p) fail(401, 'Sessiya yaroqsiz yoki tugagan. Qayta kiring.');
  return p;
}

// ---------- parol hashlari ----------
function scryptHash(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(pw), salt, 32, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt$16384$${salt}$${h}`;
}
function verifyHash(pw, stored) {
  if (typeof stored !== 'string') return false;
  const [kind, n, salt, hash] = stored.split('$');
  if (!kind || !salt || !hash) return false;
  let got;
  try {
    if (kind === 'scrypt') got = crypto.scryptSync(String(pw), salt, 32, { N: Number(n), r: 8, p: 1 });
    else if (kind === 'pbkdf2') got = crypto.pbkdf2Sync(String(pw), Buffer.from(salt, 'utf8'), Number(n), 32, 'sha256');
    else return false;
  } catch { return false; }
  const exp = Buffer.from(hash, 'hex');
  return got.length === exp.length && crypto.timingSafeEqual(got, exp);
}
const DUMMY = scryptHash('dummy-password');

// ---------- urinishlarni cheklash ----------
const MAX_FAILS = 5, STEPS = [60e3, 300e3, 900e3, 3600e3];
async function lockLeft(keys) {
  let left = 0;
  for (const key of keys) {
    const { data } = await db().from('fura_login_attempts').select('*').eq('key', key).maybeSingle();
    if (data && data.locked_until) left = Math.max(left, new Date(data.locked_until).getTime() - Date.now());
  }
  return left > 0 ? left : 0;
}
async function registerFail(keys) {
  for (const key of keys) {
    const { data } = await db().from('fura_login_attempts').select('*').eq('key', key).maybeSingle();
    let fails = (data?.fails || 0) + 1, level = data?.level || 0, until = null;
    if (fails >= MAX_FAILS) { until = new Date(Date.now() + STEPS[Math.min(level, STEPS.length - 1)]).toISOString(); level++; fails = 0; }
    await db().from('fura_login_attempts').upsert({ key, fails, level, locked_until: until, updated_at: new Date().toISOString() }, { onConflict: 'key' });
  }
}
async function clearFails(keys) { for (const key of keys) await db().from('fura_login_attempts').delete().eq('key', key); }
async function guard(keys) {
  const left = await lockLeft(keys);
  if (left) fail(429, `Juda ko‘p noto‘g‘ri urinish. ${Math.ceil(left / 60000)} daqiqadan keyin qayta urinib ko‘ring.`, { locked: true });
}
const clientIp = (event) => {
  const h = event.headers || {};
  return String(h['x-nf-client-connection-ip'] || (h['x-forwarded-for'] || '').split(',')[0] || h['client-ip'] || 'unknown').trim();
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- yordamchilar ----------
const normName = (v) => String(v || '').trim().replace(/\s+/g, ' ').toLocaleUpperCase('uz-UZ');
const normPlate = (v) => String(v || '').trim().toUpperCase();
const must = (res) => { if (res.error) fail(500, 'Ma’lumotlar bazasi xatosi.'); return res.data; };
function checkPassword(p, what = 'Parol') {
  if (typeof p !== 'string' || p.length < 4 || p.length > 64) fail(400, `${what} 4 dan 64 gacha belgi bo‘lsin.`);
}
function checkLimit(n) {
  if (!Number.isInteger(n) || n < 1 || n > 500) fail(400, 'Mashina limiti 1 dan 500 gacha butun son bo‘lsin.');
}
function checkName(n) { if (n.length < 2 || n.length > 100) fail(400, 'Firma nomi 2 dan 100 gacha belgi bo‘lsin.'); }
function checkPlate(p) { if (!p || p.length > 20) fail(400, 'Mashina raqami 1 dan 20 gacha belgi bo‘lsin.'); }
const newSalt = () => crypto.randomBytes(16).toString('hex');

async function addVehicleTo(firmId, plateRaw) {
  const plate = normPlate(plateRaw);
  checkPlate(plate);
  const firm = must(await db().from('fura_firms').select('id,vehicle_limit').eq('id', firmId).maybeSingle());
  if (!firm) fail(404, 'Firma topilmadi.');
  const mine = must(await db().from('fura_vehicles').select('id').eq('firm_id', firmId));
  if (mine.length >= firm.vehicle_limit) fail(409, `Mashina limiti tugagan (${firm.vehicle_limit} ta).`);
  const clash = must(await db().from('fura_vehicles').select('id').eq('plate', plate).maybeSingle());
  if (clash) fail(409, 'Bu mashina raqami allaqachon ishlatilgan.');
  return must(await db().from('fura_vehicles').insert({ firm_id: firmId, plate }).select('id,plate').single());
}
async function vehicleOpen(firmId, plateRaw) {
  const plate = normPlate(plateRaw);
  const veh = must(await db().from('fura_vehicles').select('id,plate').eq('plate', plate).eq('firm_id', firmId).maybeSingle());
  if (!veh) fail(404, 'Bu firmada bunday mashina yo‘q.');
  return { token: sign({ r: 'vehicle', v: veh.id, f: firmId }, 3600), vehicle: { id: veh.id, plate: veh.plate } };
}

// ---------- amallar ----------
const actions = {
  async ping() { return { ok: true, configured: configured() }; },

  // ===== OWNER =====
  async 'owner-login'(event, b) {
    if (!process.env.OWNER_HASH_1 || !process.env.OWNER_HASH_2) fail(503, 'OWNER parollari serverda sozlanmagan.');
    const keys = [`owner:${clientIp(event)}`];
    await guard(keys);
    const a = verifyHash(b.p1, process.env.OWNER_HASH_1), c = verifyHash(b.p2, process.env.OWNER_HASH_2);
    if (!(a && c)) { await registerFail(keys); await sleep(600); fail(401, 'OWNER parollari noto‘g‘ri.'); }
    await clearFails(keys);
    return { token: sign({ r: 'owner' }, 900) };
  },
  async 'owner-list'(event) {
    need(event, 'owner');
    const firms = must(await db().from('fura_firms').select('id,name,vehicle_limit,pw_enc,created_at').order('created_at', { ascending: true }));
    const vehicles = must(await db().from('fura_vehicles').select('id,firm_id,plate').order('created_at', { ascending: true }));
    return { firms: firms.map((f) => ({ id: f.id, name: f.name, limit: f.vehicle_limit, pwEnc: f.pw_enc || null, vehicles: vehicles.filter((v) => v.firm_id === f.id).map((v) => ({ id: v.id, plate: v.plate })) })) };
  },
  async 'owner-create-firm'(event, b) {
    need(event, 'owner');
    const name = normName(b.name); checkName(name); checkPassword(b.password); checkLimit(b.limit);
    const clash = must(await db().from('fura_firms').select('id').eq('name_norm', name).maybeSingle());
    if (clash) fail(409, 'Bu firma nomi oldin yaratilgan.');
    const row = must(await db().from('fura_firms').insert({ name, name_norm: name, pass_hash: scryptHash(b.password), vehicle_limit: b.limit, pw_enc: typeof b.pwEnc === 'string' ? b.pwEnc.slice(0, 2000) : null }).select('id,name').single());
    return { firm: row };
  },
  async 'owner-set-password'(event, b) {
    need(event, 'owner'); checkPassword(b.password);
    const firm = must(await db().from('fura_firms').select('id,name_norm').eq('id', b.firmId).maybeSingle());
    if (!firm) fail(404, 'Firma topilmadi.');
    must(await db().from('fura_firms').update({ pass_hash: scryptHash(b.password), pw_enc: typeof b.pwEnc === 'string' ? b.pwEnc.slice(0, 2000) : null }).eq('id', firm.id));
    await clearFails([`firm:${firm.name_norm}`]);
    return { ok: true };
  },
  async 'owner-set-limit'(event, b) {
    need(event, 'owner'); checkLimit(b.limit);
    const mine = must(await db().from('fura_vehicles').select('id').eq('firm_id', b.firmId));
    if (b.limit < mine.length) fail(409, `Limit qo‘shilgan mashinalar sonidan (${mine.length}) kam bo‘lmasin. Avval mashinani o‘chiring.`);
    must(await db().from('fura_firms').update({ vehicle_limit: b.limit }).eq('id', b.firmId));
    return { ok: true };
  },
  async 'owner-delete-firm'(event, b) {
    need(event, 'owner');
    must(await db().from('fura_firms').delete().eq('id', b.firmId));
    return { ok: true };
  },
  async 'owner-add-vehicle'(event, b) {
    need(event, 'owner');
    return { vehicle: await addVehicleTo(b.firmId, b.plate) };
  },
  async 'owner-delete-vehicle'(event, b) {
    need(event, 'owner');
    must(await db().from('fura_vehicles').delete().eq('id', b.vehicleId));
    return { ok: true };
  },
  // Shu brauzerdagi (eski, lokal) ma'lumotlarni serverga ko'chirish
  async 'owner-import'(event, b) {
    need(event, 'owner');
    if (!Array.isArray(b.firms) || b.firms.length > 500) fail(400, 'Noto‘g‘ri ma’lumot.');
    const report = [];
    for (const f of b.firms) {
      const name = normName(f.name);
      if (name.length < 2) { report.push({ name: f.name, status: 'o‘tkazib yuborildi (nomi noto‘g‘ri)' }); continue; }
      const clash = must(await db().from('fura_firms').select('id').eq('name_norm', name).maybeSingle());
      if (clash) { report.push({ name, status: 'serverda allaqachon bor' }); continue; }
      const hash = typeof f.hash === 'string' && /^(pbkdf2|scrypt)\$/.test(f.hash) ? f.hash : (typeof f.password === 'string' && f.password.length >= 4 ? scryptHash(f.password) : null);
      if (!hash) { report.push({ name, status: 'o‘tkazib yuborildi (paroli yo‘q)' }); continue; }
      const limit = Math.min(500, Math.max(1, Number(f.limit) || 1));
      const firm = must(await db().from('fura_firms').insert({ name, name_norm: name, pass_hash: hash, vehicle_limit: limit, pw_enc: typeof f.pwEnc === 'string' ? f.pwEnc.slice(0, 2000) : null }).select('id').single());
      let nv = 0, nk = 0;
      for (const v of (Array.isArray(f.vehicles) ? f.vehicles : [])) {
        const plate = normPlate(v.plate);
        if (!plate || plate.length > 20) continue;
        const vclash = must(await db().from('fura_vehicles').select('id').eq('plate', plate).maybeSingle());
        if (vclash) continue;
        const row = must(await db().from('fura_vehicles').insert({ firm_id: firm.id, plate }).select('id').single());
        nv++;
        const rows = (Array.isArray(v.kv) ? v.kv : []).filter((x) => x && typeof x.key === 'string' && x.key.length <= 100 && typeof x.value === 'string' && x.value.length <= 500000)
          .filter((x) => !x.value.startsWith('enc1:')).map((x) => ({ vehicle_id: row.id, key: x.key, value: encVal(row.id, x.key, x.value), updated_at: new Date().toISOString() }));
        for (let i = 0; i < rows.length; i += 50) must(await db().from('fura_kv').upsert(rows.slice(i, i + 50), { onConflict: 'vehicle_id,key' }));
        nk += rows.length;
      }
      report.push({ name, status: `ko‘chirildi: ${nv} mashina, ${nk} yozuv` });
    }
    return { report };
  },

  // ===== FIRMA =====
  async 'firm-login'(event, b) {
    const name = normName(b.name);
    if (!name || typeof b.password !== 'string' || !b.password) fail(400, 'Firma nomi va parolni kiriting.');
    const keys = [`firm:${name}`, `ip:${clientIp(event)}`];
    await guard(keys);
    const firm = must(await db().from('fura_firms').select('id,name,pass_hash,vehicle_limit').eq('name_norm', name).maybeSingle());
    const ok = verifyHash(b.password, firm ? firm.pass_hash : DUMMY) && !!firm;
    if (!ok) { await registerFail(keys); await sleep(400); fail(401, 'Firma nomi yoki paroli noto‘g‘ri.'); }
    await clearFails(keys.slice(0, 1));
    if (!firm.pass_hash.startsWith('scrypt$')) await db().from('fura_firms').update({ pass_hash: scryptHash(b.password) }).eq('id', firm.id);
    const vehicles = must(await db().from('fura_vehicles').select('id,plate').eq('firm_id', firm.id).order('created_at', { ascending: true }));
    return { token: sign({ r: 'firm', f: firm.id }, 3600), firm: { id: firm.id, name: firm.name, limit: firm.vehicle_limit }, vehicles };
  },
  async 'firm-add-vehicle'(event, b) {
    const t = need(event, 'firm');
    const veh = await addVehicleTo(t.f, b.plate);
    return { vehicle: { id: veh.id, plate: veh.plate } };
  },
  async 'vehicle-open'(event, b) {
    const t = need(event, 'firm');
    return vehicleOpen(t.f, b.plate);
  },

  // ===== MASHINA MA'LUMOTLARI =====
  async 'data-get'(event) {
    const t = need(event, 'vehicle');
    const rows = must(await db().from('fura_kv').select('key,value').eq('vehicle_id', t.v));
    return { items: rows.map((r) => ({ key: r.key, value: decVal(t.v, r.key, r.value) })).filter((r) => r.value !== null), token: sign({ r: 'vehicle', v: t.v, f: t.f }, 3600) };
  },
  async 'data-set'(event, b) {
    const t = need(event, 'vehicle');
    if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 100) fail(400, 'Noto‘g‘ri so‘rov.');
    const rows = b.items.map((x) => {
      if (!x || typeof x.key !== 'string' || !x.key || x.key.length > 100 || typeof x.value !== 'string' || x.value.length > 500000) fail(400, 'Noto‘g‘ri yozuv.');
      return { vehicle_id: t.v, key: x.key, value: encVal(t.v, x.key, x.value), updated_at: new Date().toISOString() };
    });
    must(await db().from('fura_kv').upsert(rows, { onConflict: 'vehicle_id,key' }));
    return { ok: true, token: sign({ r: 'vehicle', v: t.v, f: t.f }, 3600) };
  }
};

export async function handler(event) {
  if (event.httpMethod !== 'POST') return out(405, { error: 'Method not allowed' });
  let body;
  try { body = JSON.parse(event.body || '{}'); } catch { return out(400, { error: 'Noto‘g‘ri so‘rov.' }); }
  const fn = actions[body && body.action];
  if (!fn || typeof body !== 'object') return out(400, { error: 'Noma’lum amal.' });
  if (body.action !== 'ping' && !configured()) return out(503, { error: 'Server sozlanmagan.' });
  try {
    return out(200, await fn(event, body));
  } catch (e) {
    if (e instanceof HttpError) return out(e.status, { error: e.message, ...e.extra });
    console.error('API xatosi:', e && e.message);
    return out(500, { error: 'Server xatosi.' });
  }
}
