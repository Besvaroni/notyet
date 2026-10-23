# Servidor de pagos de NotYet (gratis, en Cloudflare Workers)

Comprueba con Stripe que cada pago es real, y deja recuperar el plan en otro móvil con el correo con el que se pagó. Si alguien cancela en Stripe, la app lo detecta en la siguiente comprobación semanal y vuelve al plan Gratis.

Pasos (una vez):
1. Crea una cuenta gratuita en https://dash.cloudflare.com
2. Workers & Pages > Create > Worker > nombre `notyet-pagos` > Deploy.
3. Edit code: pega el contenido de `worker.js` > Deploy.
4. Settings > Variables and Secrets > Add > Secret > nombre `STRIPE_SECRET`, valor: tu clave secreta de Stripe (Desarrolladores > Claves de API). Esta clave no se pega nunca en la web ni en el chat.
5. Copia la dirección del worker (algo como https://notyet-pagos.TU-USUARIO.workers.dev) y pásasela a Claude para ponerla en `API` de app.html.
