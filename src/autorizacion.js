/* ============================================================================
   autorizacion.js — Control de acceso
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Dos conceptos que se confunden a menudo:
     · AUTENTICACIÓN (Fase 8): comprobar quién eres.
     · AUTORIZACIÓN (este archivo): comprobar si lo que eres te permite hacer
       lo que estás pidiendo.

   REGLA CENTRAL: el rol se lee SIEMPRE de req.session, que vive en el
   servidor. Nunca de la petición, ni de una cookie legible, ni de un campo
   del formulario. Si el rol viajara por el cliente, bastaría con editarlo
   desde las herramientas del navegador para volverse administrador.
   ============================================================================ */

/** Exige una sesión iniciada. */
function requiereSesion(req, res, next) {
  if (!req.session || !req.session.usuario) {
    return res.status(401).json({ ok: false, errores: ["Debes iniciar sesión."] });
  }
  next();
}

/**
 * Exige uno de los roles indicados. Se usa DESPUÉS de requiereSesion, pero
 * comprueba la sesión igualmente: si algún día alguien monta la ruta sin el
 * primer middleware, esto no debe convertirse en una puerta abierta.
 *
 *   app.get("/usuarios", requiereSesion, requiereRol("Administrador"), ...)
 */
function requiereRol(...rolesPermitidos) {
  return function (req, res, next) {
    if (!req.session || !req.session.usuario) {
      return res.status(401).json({ ok: false, errores: ["Debes iniciar sesión."] });
    }
    if (!rolesPermitidos.includes(req.session.usuario.rol)) {
      // 403 Forbidden: sabemos quién eres, y aun así no puedes.
      return res.status(403).json({ ok: false, errores: ["No tienes permiso para esta operación."] });
    }
    next();
  };
}

/**
 * Igual que requiereSesion, pero para PÁGINAS en vez de peticiones de datos.
 * A una petición de datos se le responde 401 y el JavaScript de la página lo
 * interpreta; a alguien que escribió una dirección en el navegador hay que
 * llevarlo al login, o vería una pantalla en blanco con un JSON.
 */
function requiereSesionPagina(req, res, next) {
  // Solo se protegen las páginas, que se piden con GET o HEAD. Si este
  // middleware redirigiera también los POST, se tragaría /login y /registro,
  // y sería imposible autenticarse: haría falta sesión para poder crearla.
  if (req.method !== "GET" && req.method !== "HEAD") return next();
  if (req.session && req.session.usuario) return next();
  res.redirect("/login.html");
}

module.exports = { requiereSesion, requiereSesionPagina, requiereRol };
