// NotYet - servidor (Cloudflare Workers, plan gratuito)
// - Comprueba pagos con Stripe y deja recuperar el plan (correo + 4 ultimos digitos).
// - Cuentas con correo y contrasena. El correo se confirma una vez con un codigo; si olvidas la contrasena, te llega un codigo para cambiarla.
// - La contrasena llega ya reforzada desde el movil (PBKDF2 en el navegador) y aqui se vuelve a cifrar con sal propia: nunca se guarda en claro.
// - Guarda tus datos de la app para tenerlos en cualquier movil (base de datos D1 en la UE).
// - Invitaciones: tu amigo tiene el primer mes de Plus gratis; cuando paga su primer mes, tu ganas un mes.
// - Votaciones por enlace: los amigos votan si, no o mas barato con un toque y el resultado llega a la app. Permisos de hijos a padres.
// - Entrar con Google (Microsoft preparado): se comprueba la firma del proveedor.
// Secretos (los pega el dueno en Cloudflare, nunca en el codigo): STRIPE_SECRET (clave restringida rk_live_...), RESEND_KEY (envio de correos).
const ORIGINS = ["https://notyetapp.app", "https://www.notyetapp.app", "https://besvaroni.github.io", "https://notyet-9op.pages.dev"];
const DAY = 864e5, CODE_TTL = 10 * 60e3, SESSION_TTL = 120 * DAY, MAX_DATA = 400000, REWARD_DAYS = 30, REWARD_CENTS = 299;
const MAIL_FROM = "NotYet <codigo@notyetapp.app>";
// Entrar con Google / Microsoft: los ID de cliente son publicos (no son secretos). Microsoft vacio = desactivado
const OIDC = {
  google: { aud: "598545986571-2ul55vakdrk3jane6gscgitf98t4m8gl.apps.googleusercontent.com", jwks: "https://www.googleapis.com/oauth2/v3/certs", iss: (i) => i === "https://accounts.google.com" || i === "accounts.google.com" },
  microsoft: { aud: "", jwks: "https://login.microsoftonline.com/consumers/discovery/v2.0/keys", iss: (i) => i === "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0" },
};
const JWKS_CACHE = {};
const b64uDec = (t) => Uint8Array.from(atob(t.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((t.length + 3) % 4)), (c) => c.charCodeAt(0));
async function verifyIdToken(provider, jwt, nonce, env) {
  const cfg = OIDC[provider]; const aud = (env && env[provider.toUpperCase() + "_CLIENT_ID"]) || (cfg && cfg.aud);
  if (!cfg || !aud) return { error: "Este acceso aún no está activado" };
  const parts = String(jwt || "").split("."); if (parts.length !== 3) return { error: "Token no válido" };
  let head, pay; try { head = JSON.parse(new TextDecoder().decode(b64uDec(parts[0]))); pay = JSON.parse(new TextDecoder().decode(b64uDec(parts[1]))); } catch (e) { return { error: "Token no válido" }; }
  if (head.alg !== "RS256" || !head.kid) return { error: "Token no válido" };
  let keys = JWKS_CACHE[provider];
  if (!keys || keys.t < now() - 3600e3 || !keys.k.some((k) => k.kid === head.kid)) { const r = await fetch(cfg.jwks); keys = JWKS_CACHE[provider] = { t: now(), k: (await r.json()).keys || [] }; }
  const jwk = keys.k.find((k) => k.kid === head.kid); if (!jwk) return { error: "Token no válido" };
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDec(parts[2]), enc.encode(parts[0] + "." + parts[1]));
  if (!ok) return { error: "Token no válido" };
  const t = Math.floor(now() / 1000);
  if (pay.aud !== aud || !cfg.iss(pay.iss) || !(pay.exp > t) || (pay.iat && pay.iat > t + 300)) return { error: "Token caducado o de otra app" };
  if (!nonce || pay.nonce !== nonce) return { error: "Vuelve a intentarlo" };
  const email = String(pay.email || (provider === "microsoft" ? pay.preferred_username : "") || "").trim().toLowerCase();
  if (!okEmail(email)) return { error: "Tu cuenta no comparte el correo" };
  if (provider === "google" && pay.email_verified !== true && pay.email_verified !== "true") return { error: "Tu correo de Google no está verificado" };
  return { email, sub: pay.sub };
}

const hdr = (req) => { const o = req.headers.get("Origin") || ""; return { "Access-Control-Allow-Origin": ORIGINS.includes(o) || /^https:\/\/[a-z0-9-]+\.notyet[a-z0-9-]*\.pages\.dev$/.test(o) ? o : ORIGINS[0], "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Content-Type": "application/json", "Vary": "Origin", "Cache-Control": "no-store" }; };
const now = () => Date.now();
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const sha = async (s) => b64u(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const rnd = (n) => { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; };
const token = () => b64u(rnd(32));
const code6 = () => { const a = new Uint32Array(1); crypto.getRandomValues(a); return String(a[0] % 1000000).padStart(6, "0"); };
const refCode = () => { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", r = rnd(7); return Array.from(r, (x) => A[x % A.length]).join(""); };
const okEmail = (e) => /^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/.test(e) && e.length <= 160;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- Stripe (lectura; escritura solo para el descuento por invitar, si la clave lo permite) ----------
async function stripe(env, path, method, body) {
  const r = await fetch("https://api.stripe.com/v1/" + path, { method: method || "GET", headers: { Authorization: "Bearer " + env.STRIPE_SECRET, ...(body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}) }, body: body ? new URLSearchParams(body).toString() : undefined });
  if (!r.ok) { const e = new Error("stripe " + r.status); e.status = r.status; throw e; }
  return r.json();
}
async function planOfSub(env, sub) { const item = sub.items && sub.items.data && sub.items.data[0]; if (!item) return null; const prod = await stripe(env, "products/" + item.price.product); return /pareja/i.test(prod.name) ? "pareja" : "plus"; }
// Suscripcion vigente: activa o en el mes de prueba
async function liveSub(env, customer, paidOnly) {
  const list = await stripe(env, "subscriptions?status=all&limit=10&customer=" + encodeURIComponent(customer));
  return list.data.find((s) => s.status === "active" || (!paidOnly && s.status === "trialing")) || null;
}
async function last4s(env, customer) { const pm = await stripe(env, "payment_methods?type=card&limit=10&customer=" + encodeURIComponent(customer)); return pm.data.map((p) => p.card && p.card.last4).filter(Boolean); }
async function customersByEmail(env, email) { const cs = await stripe(env, "customers?limit=5&email=" + encodeURIComponent(email)); return cs.data.map((c) => c.id); }

// ---------- Base de datos ----------
let ready = false;
async function schema(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, ref TEXT UNIQUE NOT NULL, referred_by TEXT, created INTEGER, bonus_until INTEGER DEFAULT 0, stripe_customer TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS codes (email TEXT NOT NULL, hash TEXT NOT NULL, expires INTEGER, tries INTEGER DEFAULT 0, created INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS appdata (user_id TEXT PRIMARY KEY, json TEXT, updated INTEGER)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS referrals (referee_id TEXT PRIMARY KEY, referrer_id TEXT NOT NULL, status TEXT, created INTEGER, rewarded INTEGER, how TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS hits (k TEXT NOT NULL, t INTEGER)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS i_codes ON codes(email)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS i_ref ON referrals(referrer_id)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS i_hits ON hits(k, t)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS polls (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL, kind TEXT, title TEXT, price REAL, shop TEXT, url TEXT, emoji TEXT, asker TEXT, created INTEGER, expires INTEGER, decision TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS poll_votes (poll_id TEXT NOT NULL, voter TEXT NOT NULL, name TEXT, choice TEXT, comment TEXT, created INTEGER, PRIMARY KEY (poll_id, voter))")
  ]);
  for (const sql of ["ALTER TABLE users ADD COLUMN pw_hash TEXT", "ALTER TABLE users ADD COLUMN pw_salt TEXT", "ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 1"]) { try { await env.DB.prepare(sql).run(); } catch (e) {} }
  ready = true;
}
// Contrasenas: PBKDF2-SHA256 con sal aleatoria por usuario (la app ya envia la contrasena reforzada)
const PW_ITER = 10000;
async function pwHash(pre, saltB64) {
  const salt = saltB64 ? Uint8Array.from(atob(saltB64.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - saltB64.length % 4) % 4)), (c) => c.charCodeAt(0)) : rnd(16);
  const key = await crypto.subtle.importKey("raw", enc.encode(pre), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PW_ITER }, key, 256);
  return { hash: b64u(bits), salt: saltB64 || b64u(salt) };
}
const sameStr = (a, b) => { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; };
const okPre = (p) => typeof p === "string" && /^[A-Za-z0-9_-]{40,60}$/.test(p);
// Limite de peticiones: max n en la ventana (ms) para la clave k
async function limited(env, k, n, win) {
  const c = await env.DB.prepare("SELECT COUNT(*) AS c FROM hits WHERE k = ? AND t > ?").bind(k, now() - win).first();
  if (c && c.c >= n) return true;
  await env.DB.prepare("INSERT INTO hits (k, t) VALUES (?, ?)").bind(k, now()).run();
  if (Math.random() < 0.05) await env.DB.prepare("DELETE FROM hits WHERE t < ?").bind(now() - DAY).run();
  return false;
}
async function userFromReq(env, req) {
  const a = req.headers.get("Authorization") || ""; const m = a.match(/^Bearer ([A-Za-z0-9_-]{20,100})$/); if (!m) return null;
  const s = await env.DB.prepare("SELECT user_id, expires FROM sessions WHERE hash = ?").bind(await sha(m[1])).first();
  if (!s || s.expires < now()) return null;
  return env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(s.user_id).first();
}

// ---------- Correo ----------
const MAILS = {
  signup: ["Confirma tu correo en NotYet", "Tu código para confirmar tu correo y activar tu cuenta de NotYet es:", "Si no has creado una cuenta en NotYet, ignora este correo."],
  reset: ["Cambia tu contraseña de NotYet", "Tu código para cambiar la contraseña de NotYet es:", "Si no has pedido cambiar la contraseña, ignora este correo: tu cuenta sigue segura."]
};
async function sendCode(env, email, code, purpose) {
  const m = MAILS[purpose] || MAILS.signup;
  if (!env.RESEND_KEY) throw new Error("sin correo");
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:460px;margin:auto;padding:24px;color:#1D1D1F"><div style="font-size:22px;font-weight:800;margin-bottom:16px">NotYet</div><p>${m[1]}</p><div style="font-size:34px;font-weight:800;letter-spacing:8px;margin:18px 0">${code}</div><p style="color:#6E6E73;font-size:14px">Caduca en 10 minutos. ${m[2]}</p><p style="color:#6E6E73;font-size:12px;margin-top:24px">NotYet - notyetapp.app</p></div>`;
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM || MAIL_FROM, to: [email], subject: `${code} - ${m[0]}`, html, text: `${m[1]} ${code}. Caduca en 10 minutos. ${m[2]}` }) });
  if (!r.ok) throw new Error("resend " + r.status);
}

// ---------- Plan e invitaciones ----------
async function linkCustomer(env, u) {
  if (u.stripe_customer) return u.stripe_customer;
  try { for (const id of await customersByEmail(env, u.email)) { if (await liveSub(env, id)) { await env.DB.prepare("UPDATE users SET stripe_customer = ? WHERE id = ?").bind(id, u.id).run(); return id; } } } catch (e) {}
  return null;
}
async function planOf(env, u) {
  let plan = "gratis", source = "", until = null, trial = false;
  const cus = await linkCustomer(env, u).catch(() => null);
  if (cus) { try { const sub = await liveSub(env, cus); if (sub) { plan = await planOfSub(env, sub); source = "stripe"; until = sub.current_period_end ? sub.current_period_end * 1000 : null; trial = sub.status === "trialing"; } } catch (e) {} }
  if (plan === "gratis" && (u.bonus_until || 0) > now()) { plan = "plus"; source = "invitaciones"; until = u.bonus_until; }
  return { plan, source, until, trial };
}
// Revisa los amigos invitados: si ya pagaron su primer mes, premia a quien invito (una vez por amigo)
async function settleReferrals(env, u) {
  const pend = await env.DB.prepare("SELECT r.referee_id, x.email, x.stripe_customer FROM referrals r JOIN users x ON x.id = r.referee_id WHERE r.referrer_id = ? AND r.status = 'pending' LIMIT 10").bind(u.id).all();
  for (const p of pend.results || []) {
    try {
      let ids = p.stripe_customer ? [p.stripe_customer] : await customersByEmail(env, p.email), paid = false;
      for (const id of ids) { if (await liveSub(env, id, true)) { paid = true; break; } }
      if (!paid) continue;
      let how = "dias";
      const myCus = await linkCustomer(env, u);
      if (myCus && (await liveSub(env, myCus, true))) {
        try { await stripe(env, "customers/" + myCus + "/balance_transactions", "POST", { amount: String(-REWARD_CENTS), currency: "eur", description: "NotYet: un mes gratis por invitar a un amigo" }); how = "descuento"; } catch (e) { how = "dias"; }
      }
      if (how === "dias") { const base = Math.max(now(), u.bonus_until || 0); u.bonus_until = base + REWARD_DAYS * DAY; await env.DB.prepare("UPDATE users SET bonus_until = ? WHERE id = ?").bind(u.bonus_until, u.id).run(); }
      await env.DB.prepare("UPDATE referrals SET status = 'rewarded', rewarded = ?, how = ? WHERE referee_id = ?").bind(now(), how, p.referee_id).run();
    } catch (e) {}
  }
  const st = await env.DB.prepare("SELECT status, COUNT(*) AS c FROM referrals WHERE referrer_id = ? GROUP BY status").bind(u.id).all();
  const by = {}; (st.results || []).forEach((r) => { by[r.status] = r.c; });
  return { invited: (by.pending || 0) + (by.rewarded || 0), pending: by.pending || 0, rewarded: by.rewarded || 0 };
}

export default {
  async fetch(req, env) {
    const H = hdr(req), out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: H });
    if (req.method === "OPTIONS") return new Response(null, { headers: H });
    const url = new URL(req.url), path = url.pathname, ip = req.headers.get("CF-Connecting-IP") || "x";
    const body = async () => { if (req.method === "GET") return {}; const t = await req.text(); if (t.length > MAX_DATA + 2000) throw Object.assign(new Error("big"), { big: true }); try { return JSON.parse(t || "{}"); } catch (e) { return {}; } };
    try {
      if (env.DB) await schema(env);
      if (path === "/") return out({ ok: true, service: "notyet", cuentas: !!env.DB, correo: !!env.RESEND_KEY, stripe: !!env.STRIPE_SECRET });
      // ---- Pagos ----
      if (path === "/verify") {
        const cs = url.searchParams.get("cs") || "";
        if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(cs)) return out({ ok: false, error: "sesión no válida" }, 400);
        const s = await stripe(env, "checkout/sessions/" + cs);
        if (s.status !== "complete" || !s.customer) return out({ ok: false, error: "pago no completado" });
        const sub = await liveSub(env, s.customer);
        if (!sub) return out({ ok: false, error: "sin suscripción activa" });
        const u = env.DB ? await userFromReq(env, req) : null;
        if (u) await env.DB.prepare("UPDATE users SET stripe_customer = ? WHERE id = ?").bind(s.customer, u.id).run();
        const l4 = await last4s(env, s.customer);
        return out({ ok: true, plan: await planOfSub(env, sub), email: (s.customer_details || {}).email || "", last4: l4[0] || "", until: sub.current_period_end || null, trial: sub.status === "trialing" });
      }
      if (path === "/restore") {
        if (req.method !== "POST") return out({ ok: false, error: "usa POST" }, 405);
        if (env.DB && (await limited(env, "restore:" + ip, 10, 3600e3))) return out({ ok: false, error: "demasiados intentos, prueba en una hora" }, 429);
        const b = await body(); const email = String(b.email || "").trim().toLowerCase(), l4 = String(b.last4 || "").trim();
        if (!okEmail(email)) return out({ ok: false, error: "correo no válido" }, 400);
        if (!/^\d{4}$/.test(l4)) return out({ ok: false, error: "pon los 4 últimos dígitos de la tarjeta con la que pagaste" }, 400);
        for (const id of await customersByEmail(env, email)) { const sub = await liveSub(env, id); if (!sub) continue; if (!(await last4s(env, id)).includes(l4)) continue; return out({ ok: true, plan: await planOfSub(env, sub), email, last4: l4, until: sub.current_period_end || null }); }
        await wait(600);
        return out({ ok: false, error: "no hay una suscripción activa con ese correo y esa tarjeta" });
      }
      if (!env.DB) return out({ ok: true, service: "notyet", cuentas: false });
      // ---- Cuentas ----
      const em = (x) => String(x || "").trim().toLowerCase();
      const newSession = async (uid) => { const t = token(); await env.DB.prepare("INSERT INTO sessions (hash, user_id, expires) VALUES (?, ?, ?)").bind(await sha(t), uid, now() + SESSION_TTL).run(); return t; };
      const issueCode = async (email, purpose) => {
        if ((await limited(env, "mailip:" + ip, 8, 3600e3)) || (await limited(env, "mail:" + email, 3, 15 * 60e3))) return { ok: false, error: "Has pedido varios códigos seguidos. Espera unos minutos.", status: 429 };
        const code = code6();
        await env.DB.batch([env.DB.prepare("DELETE FROM codes WHERE email = ?").bind(email), env.DB.prepare("INSERT INTO codes (email, hash, expires, tries, created) VALUES (?, ?, ?, 0, ?)").bind(email, await sha(email + ":" + purpose + ":" + code), now() + CODE_TTL, now())]);
        try { await sendCode(env, email, code, purpose); } catch (e) { return { ok: false, error: "No he podido enviar el correo ahora. Prueba en un rato.", status: 503 }; }
        return { ok: true };
      };
      const checkCode = async (email, purpose, code) => {
        const c = await env.DB.prepare("SELECT hash, expires, tries FROM codes WHERE email = ?").bind(email).first();
        if (!c || c.expires < now() || c.tries >= 5) return "El código ha caducado. Pide uno nuevo.";
        if (c.hash !== (await sha(email + ":" + purpose + ":" + code))) { await env.DB.prepare("UPDATE codes SET tries = tries + 1 WHERE email = ?").bind(email).run(); return "Código incorrecto"; }
        await env.DB.prepare("DELETE FROM codes WHERE email = ?").bind(email).run();
        return "";
      };
      // ---- Votaciones por enlace: tus amigos votan con un toque desde WhatsApp, Telegram o donde sea, sin cuenta ----
      const clip = (x, n) => String(x == null ? "" : x).replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n);
      const pollM = path.match(/^\/poll\/([A-Za-z0-9_-]{10,24})(\/vote|\/decide)?$/);
      if (path === "/poll" && req.method === "POST") {
        if (await limited(env, "pollnew:" + ip, 30, 3600e3)) return out({ ok: false, error: "Has creado muchas votaciones seguidas. Espera un rato." }, 429);
        const b = await body(); const title = clip(b.title, 120); if (!title) return out({ ok: false, error: "Falta qué quieres comprar" }, 400);
        const id = b64u(rnd(9)), key = token(); const url = /^https:\/\/[^\s]{4,400}$/.test(String(b.url || "")) ? String(b.url) : "";
        await env.DB.prepare("INSERT INTO polls (id, key_hash, kind, title, price, shop, url, emoji, asker, created, expires) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, await sha(key), b.kind === "permiso" ? "permiso" : "voto", title, Math.max(0, Math.min(1e6, Number(b.price) || 0)), clip(b.shop, 40), url, clip(b.emoji, 8), clip(b.asker, 30), now(), now() + 21 * DAY).run();
        return out({ ok: true, id, key, link: "https://notyetapp.app/votar?p=" + id });
      }
      if (pollM && !pollM[2] && req.method === "GET") {
        const p = await env.DB.prepare("SELECT * FROM polls WHERE id = ?").bind(pollM[1]).first(); if (!p) return out({ ok: false, error: "Esta votación no existe" }, 404);
        const v = await env.DB.prepare("SELECT voter, name, choice, comment, created FROM poll_votes WHERE poll_id = ? ORDER BY created LIMIT 60").bind(p.id).all();
        const votes = (v.results || []).map((x) => ({ id: x.voter.slice(0, 8), name: x.name, choice: x.choice, comment: x.comment, at: x.created }));
        return out({ ok: true, poll: { id: p.id, kind: p.kind, title: p.title, price: p.price, shop: p.shop, url: p.url, emoji: p.emoji, asker: p.asker, created: p.created, open: p.expires > now() && !p.decision, decision: p.decision || null }, votes });
      }
      if (pollM && pollM[2] === "/vote" && req.method === "POST") {
        if (await limited(env, "vote:" + ip, 60, 3600e3)) return out({ ok: false, error: "Demasiados votos seguidos. Espera un rato." }, 429);
        const p = await env.DB.prepare("SELECT id, expires, decision FROM polls WHERE id = ?").bind(pollM[1]).first(); if (!p) return out({ ok: false, error: "Esta votación no existe" }, 404);
        if (p.expires < now() || p.decision) return out({ ok: false, error: "Esta votación ya está cerrada" }, 409);
        const b = await body(); const choice = ["si", "no", "barato"].includes(b.choice) ? b.choice : ""; if (!choice) return out({ ok: false, error: "Elige una opción" }, 400);
        const voter = /^[A-Za-z0-9_-]{12,40}$/.test(String(b.voter || "")) ? String(b.voter) : "ip-" + (await sha(ip + p.id)).slice(0, 16);
        const c = await env.DB.prepare("SELECT COUNT(*) AS c FROM poll_votes WHERE poll_id = ?").bind(p.id).first(); if (c && c.c >= 60) return out({ ok: false, error: "Esta votación ya tiene muchos votos" }, 409);
        await env.DB.prepare("INSERT INTO poll_votes (poll_id, voter, name, choice, comment, created) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(poll_id, voter) DO UPDATE SET name = excluded.name, choice = excluded.choice, comment = excluded.comment, created = excluded.created").bind(p.id, voter, clip(b.name, 30) || "Alguien", choice, clip(b.comment, 200), now()).run();
        return out({ ok: true });
      }
      if (pollM && pollM[2] === "/decide" && req.method === "POST") {
        const b = await body(); const p = await env.DB.prepare("SELECT id, key_hash FROM polls WHERE id = ?").bind(pollM[1]).first(); if (!p) return out({ ok: false, error: "Esta votación no existe" }, 404);
        if (!sameStr(await sha(String(b.key || "")), p.key_hash)) return out({ ok: false, error: "No puedes cerrar esta votación" }, 403);
        await env.DB.prepare("UPDATE polls SET decision = ? WHERE id = ?").bind(clip(b.decision, 20) || "cerrada", p.id).run();
        return out({ ok: true });
      }
      // Entrar con Google o Microsoft (Outlook, Hotmail): el proveedor ya confirma el correo
      if (path === "/auth/oidc" && req.method === "POST") {
        const b = await body(); const provider = b.provider === "microsoft" ? "microsoft" : "google";
        if (await limited(env, "oidc:" + ip, 40, 3600e3)) return out({ ok: false, error: "Demasiados intentos. Espera un rato." }, 429);
        const v = await verifyIdToken(provider, b.id_token, String(b.nonce || ""), env); if (v.error) return out({ ok: false, error: v.error }, 400);
        const ref = String(b.ref || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
        let u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(v.email).first(), isNew = false;
        if (!u) {
          const id = b64u(rnd(12)); let r = refCode();
          for (let i = 0; i < 4 && (await env.DB.prepare("SELECT 1 FROM users WHERE ref = ?").bind(r).first()); i++) r = refCode();
          const by = ref ? await env.DB.prepare("SELECT id, email FROM users WHERE ref = ?").bind(ref).first() : null;
          await env.DB.prepare("INSERT INTO users (id, email, ref, referred_by, created, bonus_until, verified) VALUES (?, ?, ?, ?, ?, 0, 1)").bind(id, v.email, r, by && by.email !== v.email ? by.id : null, now()).run();
          u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first(); isNew = true;
          if (u.referred_by) await env.DB.prepare("INSERT OR IGNORE INTO referrals (referee_id, referrer_id, status, created) VALUES (?, ?, 'pending', ?)").bind(u.id, u.referred_by, now()).run();
        } else if (!u.verified) {
          // cuenta a medias con ese correo: la confirma el proveedor y se borra la contrasena que nadie habia confirmado
          await env.DB.prepare("UPDATE users SET verified = 1, pw_hash = NULL, pw_salt = NULL WHERE id = ?").bind(u.id).run();
        }
        return out({ ok: true, token: await newSession(u.id), email: v.email, isNew, invited: !!u.referred_by });
      }
      // Crear cuenta: correo + contrasena; se confirma el correo con un codigo
      if (path === "/auth/register" && req.method === "POST") {
        const b = await body(); const email = em(b.email), ref = String(b.ref || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
        if (!okEmail(email)) return out({ ok: false, error: "Pon un correo válido" }, 400);
        if (!okPre(b.pw)) return out({ ok: false, error: "La contraseña no es válida" }, 400);
        let u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (u && u.verified) return out({ ok: false, exists: true, error: u.pw_hash ? "Ya hay una cuenta con ese correo. Entra con tu contraseña o pulsa ¿Has olvidado tu contraseña?" : "Ya hay una cuenta con ese correo. Pulsa ¿Has olvidado tu contraseña? para ponerle contraseña." }, 409);
        const h = await pwHash(b.pw);
        if (!u) {
          const id = b64u(rnd(12)); let r = refCode();
          for (let i = 0; i < 4 && (await env.DB.prepare("SELECT 1 FROM users WHERE ref = ?").bind(r).first()); i++) r = refCode();
          const by = ref ? await env.DB.prepare("SELECT id, email FROM users WHERE ref = ?").bind(ref).first() : null;
          await env.DB.prepare("INSERT INTO users (id, email, ref, referred_by, created, bonus_until, pw_hash, pw_salt, verified) VALUES (?, ?, ?, ?, ?, 0, ?, ?, 0)").bind(id, email, r, by && by.email !== email ? by.id : null, now(), h.hash, h.salt).run();
        } else {
          // cuenta aun sin confirmar: se guarda la nueva contrasena y se confirma con el codigo del correo
          await env.DB.prepare("UPDATE users SET pw_hash = ?, pw_salt = ? WHERE id = ?").bind(h.hash, h.salt, u.id).run();
        }
        const sent = await issueCode(email, "signup");
        if (!sent.ok) return out(sent, sent.status);
        return out({ ok: true, needCode: true });
      }
      if (path === "/auth/confirm" && req.method === "POST") {
        const b = await body(); const email = em(b.email), code = String(b.code || "").replace(/\D/g, "");
        if (!okEmail(email) || code.length !== 6) return out({ ok: false, error: "Pon el código de 6 cifras" }, 400);
        if (await limited(env, "verify:" + ip, 20, 3600e3)) return out({ ok: false, error: "Demasiados intentos. Espera un rato." }, 429);
        const err = await checkCode(email, "signup", code); if (err) return out({ ok: false, error: err }, 400);
        const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first(); if (!u) return out({ ok: false, error: "Vuelve a crear la cuenta" }, 400);
        await env.DB.prepare("UPDATE users SET verified = 1 WHERE id = ?").bind(u.id).run();
        if (u.referred_by) await env.DB.prepare("INSERT OR IGNORE INTO referrals (referee_id, referrer_id, status, created) VALUES (?, ?, 'pending', ?)").bind(u.id, u.referred_by, now()).run();
        return out({ ok: true, token: await newSession(u.id), isNew: true, invited: !!u.referred_by });
      }
      if (path === "/auth/resend" && req.method === "POST") {
        const b = await body(); const email = em(b.email), purpose = b.purpose === "reset" ? "reset" : "signup";
        if (!okEmail(email)) return out({ ok: false, error: "Pon un correo válido" }, 400);
        const u = await env.DB.prepare("SELECT verified FROM users WHERE email = ?").bind(email).first();
        if (u && (purpose === "reset" || !u.verified)) { const sent = await issueCode(email, purpose); if (!sent.ok) return out(sent, sent.status); }
        return out({ ok: true });
      }
      // Entrar con correo y contrasena
      if (path === "/auth/login" && req.method === "POST") {
        const b = await body(); const email = em(b.email);
        if (!okEmail(email) || !okPre(b.pw)) return out({ ok: false, error: "Pon tu correo y tu contraseña" }, 400);
        if ((await limited(env, "login:" + ip, 30, 3600e3)) || (await limited(env, "loginmail:" + email, 8, 15 * 60e3))) return out({ ok: false, error: "Demasiados intentos. Espera 15 minutos o cambia tu contraseña." }, 429);
        const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
        if (u && !u.pw_hash) return out({ ok: false, noPassword: true, error: "Tu cuenta aún no tiene contraseña. Pulsa ¿Has olvidado tu contraseña? para crearla." }, 400);
        const h = u && u.pw_salt ? await pwHash(b.pw, u.pw_salt) : await pwHash(b.pw);
        if (!u || !sameStr(h.hash, u.pw_hash)) return out({ ok: false, error: "Correo o contraseña incorrectos" }, 400);
        if (!u.verified) { const sent = await issueCode(email, "signup"); return out({ ok: false, needCode: true, error: sent.ok ? "Falta confirmar tu correo: te hemos enviado un código." : sent.error }, 403); }
        return out({ ok: true, token: await newSession(u.id), invited: !!u.referred_by });
      }
      // He olvidado mi contrasena: codigo al correo y nueva contrasena
      if (path === "/auth/forgot" && req.method === "POST") {
        const b = await body(); const email = em(b.email);
        if (!okEmail(email)) return out({ ok: false, error: "Pon un correo válido" }, 400);
        const u = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
        if (u) { const sent = await issueCode(email, "reset"); if (!sent.ok && sent.status === 429) return out(sent, 429); } else await wait(400);
        return out({ ok: true });
      }
      if (path === "/auth/reset" && req.method === "POST") {
        const b = await body(); const email = em(b.email), code = String(b.code || "").replace(/\D/g, "");
        if (!okEmail(email) || code.length !== 6) return out({ ok: false, error: "Pon el código de 6 cifras" }, 400);
        if (!okPre(b.pw)) return out({ ok: false, error: "La contraseña no es válida" }, 400);
        if (await limited(env, "verify:" + ip, 20, 3600e3)) return out({ ok: false, error: "Demasiados intentos. Espera un rato." }, 429);
        const err = await checkCode(email, "reset", code); if (err) return out({ ok: false, error: err }, 400);
        const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first(); if (!u) return out({ ok: false, error: "No hay ninguna cuenta con ese correo" }, 400);
        const h = await pwHash(b.pw);
        await env.DB.batch([env.DB.prepare("UPDATE users SET pw_hash = ?, pw_salt = ?, verified = 1 WHERE id = ?").bind(h.hash, h.salt, u.id), env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id)]);
        if (!u.verified && u.referred_by) await env.DB.prepare("INSERT OR IGNORE INTO referrals (referee_id, referrer_id, status, created) VALUES (?, ?, 'pending', ?)").bind(u.id, u.referred_by, now()).run();
        return out({ ok: true, token: await newSession(u.id) });
      }
      const u = await userFromReq(env, req);
      if (!u) return out({ ok: false, error: "sesión caducada", auth: false }, 401);
      if (path === "/me") {
        const refs = await settleReferrals(env, u).catch(() => ({ invited: 0, pending: 0, rewarded: 0 }));
        const p = await planOf(env, u);
        const d = await env.DB.prepare("SELECT updated FROM appdata WHERE user_id = ?").bind(u.id).first();
        return out({ ok: true, email: u.email, ref: u.ref, invited: !!u.referred_by, created: u.created, plan: p.plan, source: p.source, until: p.until, trial: p.trial, bonus_until: u.bonus_until || 0, refs, synced: d ? d.updated : null });
      }
      if (path === "/data" && req.method === "GET") {
        const d = await env.DB.prepare("SELECT json, updated FROM appdata WHERE user_id = ?").bind(u.id).first();
        return out({ ok: true, data: d ? JSON.parse(d.json) : null, updated: d ? d.updated : null });
      }
      if (path === "/data" && req.method === "PUT") {
        const b = await body(); const json = JSON.stringify(b.data || null);
        if (json.length > MAX_DATA) return out({ ok: false, error: "demasiados datos" }, 413);
        await env.DB.prepare("INSERT INTO appdata (user_id, json, updated) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET json = excluded.json, updated = excluded.updated").bind(u.id, json, now()).run();
        return out({ ok: true, updated: now() });
      }
      if (path === "/auth/logout" && req.method === "POST") {
        const a = (req.headers.get("Authorization") || "").slice(7);
        await env.DB.prepare("DELETE FROM sessions WHERE hash = ?").bind(await sha(a)).run();
        return out({ ok: true });
      }
      if (path === "/account/delete" && req.method === "POST") {
        await env.DB.batch([
          env.DB.prepare("DELETE FROM appdata WHERE user_id = ?").bind(u.id),
          env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(u.id),
          env.DB.prepare("DELETE FROM referrals WHERE referee_id = ? OR referrer_id = ?").bind(u.id, u.id),
          env.DB.prepare("DELETE FROM codes WHERE email = ?").bind(u.email),
          env.DB.prepare("DELETE FROM users WHERE id = ?").bind(u.id)
        ]);
        return out({ ok: true });
      }
      return out({ ok: false, error: "no encontrado" }, 404);
    } catch (e) {
      if (e.big) return out({ ok: false, error: "demasiados datos" }, 413);
      return out({ ok: false, error: e.status ? "no se pudo consultar Stripe" : "error del servidor" }, 502);
    }
  }
};
