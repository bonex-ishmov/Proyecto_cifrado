/* ============================================================================
   panel.js — Datos de los paneles
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Igual que registro.js y login.js: devuelve { estado, cuerpo } para que la
   lógica se pueda probar sin levantar el servidor.

   Quién puede llamar a cada función NO se decide aquí, sino en las rutas de
   server.js con los middlewares de autorizacion.js. Este archivo asume que el
   permiso ya se comprobó.
   ============================================================================ */

const db = require("./db.js");

/* ---------------------------------------------------------------------------
   Panel del usuario: solo sus propios datos.
--------------------------------------------------------------------------- */
function perfil(usuarioSesion) {
  const usuario = db.buscarUsuarioPorId(usuarioSesion.id);
  if (!usuario) {
    // La cuenta se borró mientras la sesión seguía viva.
    return { estado: 401, cuerpo: { ok: false, errores: ["La cuenta ya no existe."] } };
  }
  return {
    estado: 200,
    cuerpo: {
      ok: true,
      perfil: {
        username: usuario.username,
        rol: usuario.rol,
        ultimoAcceso: usuario.ultimo_acceso,
        intentosFallidos: usuario.intentos_fallidos
      }
    }
  };
}

/* ---------------------------------------------------------------------------
   Panel del administrador: todas las cuentas y su estado de bloqueo.
   listarUsuarios() no devuelve los hashes; aquí se le añade el estado de
   bloqueo ya calculado, para que la página no tenga que interpretar fechas.
--------------------------------------------------------------------------- */
function listadoUsuarios() {
  const usuarios = db.listarUsuarios().map((u) => ({
    ...u,
    bloqueada: db.estaBloqueada(u),
    segundosRestantes: db.segundosDeBloqueo(u)
  }));
  return { estado: 200, cuerpo: { ok: true, usuarios } };
}

/**
 * Desbloquea una cuenta: pone el contador de fallos en cero y borra la fecha
 * de bloqueo. Es la acción que permite seguir la demostración en vivo después
 * de haber bloqueado una cuenta a propósito.
 */
function desbloquearUsuario(idCrudo) {
  const id = Number(idCrudo);
  if (!Number.isInteger(id) || id <= 0) {
    return { estado: 400, cuerpo: { ok: false, errores: ["Identificador de usuario inválido."] } };
  }

  const usuario = db.buscarUsuarioPorId(id);
  if (!usuario) {
    return { estado: 404, cuerpo: { ok: false, errores: ["El usuario no existe."] } };
  }

  db.desbloquearCuenta(id);
  return {
    estado: 200,
    cuerpo: { ok: true, mensaje: `La cuenta de ${usuario.username} quedó desbloqueada.` }
  };
}

module.exports = { perfil, listadoUsuarios, desbloquearUsuario };
