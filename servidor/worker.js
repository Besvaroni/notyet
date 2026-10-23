// NotYet - servidor (Cloudflare Workers, plan gratuito)
// - Comprueba pagos con Stripe y deja recuperar el plan (correo + 4 ultimos digitos).
// - Cuentas sin contrasena: entras con un codigo de 6 cifras que llega a tu correo.
// - Guarda tus datos de la app para tenerlos en cualquier movil (base de datos D1 en la UE).
// - Invitaciones: tu amigo tiene el primer mes de Plus gratis; cuando paga su primer mes, tu ganas un mes.
// Secretos (los pega el dueno en Cloudflare, nunca en el codigo): STRIPE_SECRET (clave restringida rk_live_...), RESEND_KEY (envio de correos).
const ORIGINS = ["https://notyetapp.app", "https://www.notyetapp.app", "https://besvaroni.github.io", "https://notyet-9op.pages.dev"];
const DAY = 864e5, CODE_TTL = 10 * 60e3, SESSION_TTL = 120 * DAY, MAX_DATA = 400000, REWARD_DAYS = 30, REWARD_CENTS = 299;
const MAIL_FROM = "NotYet <codigo@notyetapp.app>";

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
    env.DB.prepare("CREATE INDEX IF NOT EXISTS i_hits ON hits(k, t)")
  ]);
  ready = true;
}
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
async function sendCode(env, email, code) {
  if (!env.RESEND_KEY) throw new Error("sin correo");
  const html = `<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:460px;margin:auto;padding:24px;color:#1D1D1F"><div style="font-size:22px;font-weight:800;margin-bottom:16px">NotYet</div><p>Tu código para entrar en NotYet es:</p><div style="font-size:34px;font-weight:800;letter-spacing:8px;margin:18px 0">${code}</div><p style="color:#6E6E73;font-size:14px">Caduca en 10 minutos. Si no lo has pedido tú, ignora este correo: nadie puede entrar sin el código.</p><p style="color:#6E6E73;font-size:12px;margin-top:24px">NotYet - notyetapp.app</p></div>`;
  const r = await fetch("https://api.resend.com/emails", { method: "POST", headers: { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" }, body: JSON.stringify({ from: env.MAIL_FROM || MAIL_FROM, to: [email], subject: `${code} es tu código de NotYet`, html, text: `Tu código para entrar en NotYet es ${code}. Caduca en 10 minutos. Si no lo has pedido tú, ignora este correo.` }) });
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
      if (path === "/auth/start" && req.method === "POST") {
        const b = await body(); const email = String(b.email || "").trim().toLowerCase();
        if (!okEmail(email)) return out({ ok: false, error: "correo no válido" }, 400);
        if ((await limited(env, "start:" + ip, 8, 3600e3)) || (await limited(env, "mail:" + email, 3, 15 * 60e3))) return out({ ok: false, error: "Has pedido varios códigos seguidos. Espera unos minutos." }, 429);
        const code = code6();
        await env.DB.batch([env.DB.prepare("DELETE FROM codes WHERE email = ?").bind(email), env.DB.prepare("INSERT INTO codes (email, hash, expires, tries, created) VALUES (?, ?, ?, 0, ?)").bind(email, await sha(email + ":" + code), now() + CODE_TTL, now())]);
        try { await sendCode(env, email, code); } catch (e) { return out({ ok: false, error: "No he podido enviar el correo ahora. Prueba en un rato." }, 503); }
        return out({ ok: true });
      }
      if (path === "/auth/verify" && req.method === "POST") {
        const b = await body(); const email = String(b.email || "").trim().toLowerCase(), code = String(b.code || "").replace(/\D/g, ""), ref = String(b.ref || "").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
        if (!okEmail(email) || code.length !== 6) return out({ ok: false, error: "Pon el código de 6 cifras" }, 400);
        if (await limited(env, "verify:" + ip, 20, 3600e3)) return out({ ok: false, error: "Demasiados intentos. Espera un rato." }, 429);
        const c = await env.DB.prepare("SELECT hash, expires, tries FROM codes WHERE email = ?").bind(email).first();
        if (!c || c.expires < now() || c.tries >= 5) return out({ ok: false, error: "El código ha caducado. Pide uno nuevo." }, 400);
        if (c.hash !== (await sha(email + ":" + code))) { await env.DB.prepare("UPDATE codes SET tries = tries + 1 WHERE email = ?").bind(email).run(); return out({ ok: false, error: "Código incorrecto" }, 400); }
        await env.DB.prepare("DELETE FROM codes WHERE email = ?").bind(email).run();
        let u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first(), isNew = false;
        if (!u) {
          isNew = true; const id = b64u(rnd(12)); let r = refCode();
          for (let i = 0; i < 4 && (await env.DB.prepare("SELECT 1 FROM users WHERE ref = ?").bind(r).first()); i++) r = refCode();
          const by = ref ? await env.DB.prepare("SELECT id, email FROM users WHERE ref = ?").bind(ref).first() : null;
          await env.DB.prepare("INSERT INTO users (id, email, ref, referred_by, created, bonus_until) VALUES (?, ?, ?, ?, ?, 0)").bind(id, email, r, by && by.email !== email ? by.id : null, now()).run();
          if (by && by.email !== email) await env.DB.prepare("INSERT OR IGNORE INTO referrals (referee_id, referrer_id, status, created) VALUES (?, ?, 'pending', ?)").bind(id, by.id, now()).run();
          u = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
        }
        const t = token();
        await env.DB.prepare("INSERT INTO sessions (hash, user_id, expires) VALUES (?, ?, ?)").bind(await sha(t), u.id, now() + SESSION_TTL).run();
        return out({ ok: true, token: t, isNew, invited: !!u.referred_by });
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
