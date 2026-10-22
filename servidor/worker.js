// NotYet - servidor de comprobación de pagos (Cloudflare Workers, plan gratuito)
// Comprueba con Stripe que un pago es real y deja recuperar el plan en otro móvil con el correo de pago.
// Secreto necesario (lo pega el dueño en Cloudflare, nunca en el código): STRIPE_SECRET (clave secreta de Stripe, sk_live_... o sk_test_...)
const ORIGIN = "https://besvaroni.github.io";
const cors = { "Access-Control-Allow-Origin": ORIGIN, "Access-Control-Allow-Methods": "GET", "Content-Type": "application/json" };
const out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: cors });
async function stripe(env, path) {
  const r = await fetch("https://api.stripe.com/v1/" + path, { headers: { Authorization: "Bearer " + env.STRIPE_SECRET } });
  if (!r.ok) throw new Error("stripe " + r.status);
  return r.json();
}
// El plan sale del nombre del producto en Stripe: "NotYet Pareja" o "NotYet Plus"
async function planOfSub(env, sub) {
  const item = sub.items && sub.items.data && sub.items.data[0];
  if (!item) return null;
  const prod = await stripe(env, "products/" + item.price.product);
  return /pareja/i.test(prod.name) ? "pareja" : "plus";
}
async function activeSub(env, customer) {
  const list = await stripe(env, "subscriptions?status=active&limit=5&customer=" + encodeURIComponent(customer));
  return list.data[0] || null;
}
export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/verify") {
        const cs = url.searchParams.get("cs") || "";
        if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(cs)) return out({ ok: false, error: "sesión no válida" }, 400);
        const s = await stripe(env, "checkout/sessions/" + cs);
        if (s.status !== "complete" || !s.customer) return out({ ok: false, error: "pago no completado" });
        const sub = await activeSub(env, s.customer);
        if (!sub) return out({ ok: false, error: "sin suscripción activa" });
        return out({ ok: true, plan: await planOfSub(env, sub), email: (s.customer_details || {}).email || "", until: sub.current_period_end || null });
      }
      if (url.pathname === "/restore") {
        const email = (url.searchParams.get("email") || "").trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return out({ ok: false, error: "correo no válido" }, 400);
        const cs = await stripe(env, "customers?limit=5&email=" + encodeURIComponent(email));
        for (const c of cs.data) { const sub = await activeSub(env, c.id); if (sub) return out({ ok: true, plan: await planOfSub(env, sub), email, until: sub.current_period_end || null }); }
        return out({ ok: false, error: "no hay suscripción activa con ese correo" });
      }
      return out({ ok: true, service: "notyet" });
    } catch (e) { return out({ ok: false, error: "no se pudo consultar Stripe" }, 502); }
  }
};
