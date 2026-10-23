// NotYet - servidor de comprobacion de pagos (Cloudflare Workers, plan gratuito)
// Comprueba con Stripe que un pago es real y deja recuperar el plan en otro movil con el correo y los 4 ultimos digitos de la tarjeta.
// /restore va por POST para que el correo no quede en las direcciones que guardan los registros. No guarda nada.
// Secreto necesario (lo pega el dueno en Cloudflare, nunca en el codigo): STRIPE_SECRET
// Usa una clave restringida de Stripe (rk_live_...) con permiso de solo lectura en: Checkout Sessions, Customers, Subscriptions, Products y PaymentMethods.
const ORIGINS = ["https://besvaroni.github.io", "https://notyetapp.app", "https://www.notyetapp.app", "https://notyet.pages.dev"];
const hdr = (req) => { const o = req.headers.get("Origin") || ""; return { "Access-Control-Allow-Origin": ORIGINS.includes(o) || /^https:\/\/[a-z0-9-]+\.notyet[a-z0-9-]*\.pages\.dev$/.test(o) ? o : ORIGINS[1], "Access-Control-Allow-Methods": "GET, POST", "Access-Control-Allow-Headers": "Content-Type", "Content-Type": "application/json", "Vary": "Origin", "Cache-Control": "no-store" }; };
async function stripe(env, path) { const r = await fetch("https://api.stripe.com/v1/" + path, { headers: { Authorization: "Bearer " + env.STRIPE_SECRET } }); if (!r.ok) throw new Error("stripe " + r.status); return r.json(); }
async function planOfSub(env, sub) { const item = sub.items && sub.items.data && sub.items.data[0]; if (!item) return null; const prod = await stripe(env, "products/" + item.price.product); return /pareja/i.test(prod.name) ? "pareja" : "plus"; }
async function activeSub(env, customer) { const list = await stripe(env, "subscriptions?status=active&limit=5&customer=" + encodeURIComponent(customer)); return list.data[0] || null; }
async function last4s(env, customer) { const pm = await stripe(env, "payment_methods?type=card&limit=10&customer=" + encodeURIComponent(customer)); return pm.data.map((p) => p.card && p.card.last4).filter(Boolean); }
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
export default {
  async fetch(req, env) {
    const H = hdr(req), out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: H });
    if (req.method === "OPTIONS") return new Response(null, { headers: H });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/verify") {
        const cs = url.searchParams.get("cs") || "";
        if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(cs)) return out({ ok: false, error: "sesion no valida" }, 400);
        const s = await stripe(env, "checkout/sessions/" + cs);
        if (s.status !== "complete" || !s.customer) return out({ ok: false, error: "pago no completado" });
        const sub = await activeSub(env, s.customer);
        if (!sub) return out({ ok: false, error: "sin suscripcion activa" });
        const l4 = await last4s(env, s.customer);
        return out({ ok: true, plan: await planOfSub(env, sub), email: (s.customer_details || {}).email || "", last4: l4[0] || "", until: sub.current_period_end || null });
      }
      if (url.pathname === "/restore") {
        if (req.method !== "POST") return out({ ok: false, error: "usa POST" }, 405);
        let b = {}; try { b = await req.json(); } catch (e) {}
        const email = String(b.email || "").trim().toLowerCase(), l4 = String(b.last4 || "").trim();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return out({ ok: false, error: "correo no valido" }, 400);
        if (!/^\d{4}$/.test(l4)) return out({ ok: false, error: "pon los 4 ultimos digitos de la tarjeta con la que pagaste" }, 400);
        const cs = await stripe(env, "customers?limit=5&email=" + encodeURIComponent(email));
        for (const c of cs.data) {
          const sub = await activeSub(env, c.id); if (!sub) continue;
          if (!(await last4s(env, c.id)).includes(l4)) continue;
          return out({ ok: true, plan: await planOfSub(env, sub), email, last4: l4, until: sub.current_period_end || null });
        }
        await wait(600); // misma respuesta y tiempo parecido si el correo no existe o la tarjeta no coincide
        return out({ ok: false, error: "no hay una suscripcion activa con ese correo y esa tarjeta" });
      }
      return out({ ok: true, service: "notyet" });
    } catch (e) { return out({ ok: false, error: "no se pudo consultar Stripe" }, 502); }
  }
};
