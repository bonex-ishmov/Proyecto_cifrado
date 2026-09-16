/* ============================================================================
   login.js — Verificación de credenciales y bloqueo por cuenta
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Esta es la primera de las dos defensas contra fuerza bruta del proyecto:

     · BLOQUEO POR CUENTA (aquí): cuenta los fallos consecutivos de UN usuario
       y bloquea esa cuenta, sin importar desde qué IP vengan. Protege a un
       usuario concreto frente a un atacante que reparte el ataque entre
       muchas direcciones.

     · BLOQUEO POR IP (src/fuerzaBruta.js, Fase 9): cuenta las peticiones de UNA
       dirección IP y la bloquea, sin importar a qué cuenta apunten. Protege al
       servidor frente a quien prueba miles de usuarios distintos.

   Ninguna de las dos sustituye a la otra.

   Como en registro.js, se devuelve { estado, cuerpo } en vez de escribir la
   respuesta HTTP, para poder probar la lógica sin levantar el servidor.
   ============================================================================ */

const db = require("./db.js");
const hash = require("./hash.js");

/** Fallos consecutivos permitidos antes de bloquear la cuenta. */
const MAX_INTENTOS_CUENTA = 5;

/** Duración del bloqueo temporal de la cuenta. */
const MINUTOS_BLOQUEO = 15;

/**
 * Mensaje ÚNICO para credenciales inválidas. Da igual si el usuario no existe
 * o si existe pero la contraseña está mal: la respuesta es idéntica. Si se
 * distinguieran, un atacante podría averiguar qué cuentas existen probando
 * nombres, que es la mitad del trabajo de un ataque de fuerza bruta.
 */
const MENSAJE_CREDENCIALES = "Usuario o contraseña incorrectos.";

/**
 * Hash señuelo, usado cuando el usuario NO existe.
 * Sin esto, un usuario inexistente respondería en un milisegundo y uno
 * existente en cien (lo que tarda BCrypt), y esa diferencia de tiempo delataría
 * qué cuentas existen. Comparando contra este hash, ambos casos tardan igual.
 * Es el hash de ejemplo que aparece en la guía del laboratorio.
 */
const HASH_SENUELO = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

function respuestaBloqueo(usuario) {
  const segundos = db.segundosDeBloqueo(usuario);
  const minutos = Math.ceil(segundos / 60);
  return {
    estado: 423, // 423 Locked: la cuenta está bloqueada.
    cuerpo: {
      ok: false,
      bloqueado: true,
      segundosRestantes: segundos,
      errores: [`La cuenta está bloqueada temporalmente por intentos fallidos. ` +
                `Vuelve a intentarlo en ${minutos} minuto${minutos === 1 ? "" : "s"}.`]
    }
  };
}

/**
 * Verifica credenciales y aplica la política de bloqueo por cuenta.
 * @returns {{estado:number, cuerpo:object, usuario?:object}}
 *          `usuario` solo viene cuando la autenticación fue correcta, y trae
 *          únicamente lo que puede guardarse en la sesión (nunca el hash).
 */
async function autenticar(datos = {}) {
  const username = typeof datos.username === "string" ? datos.username.trim() : "";
  const password = typeof datos.password === "string" ? datos.password : "";

  if (username === "" || password === "") {
    return { estado: 400, cuerpo: { ok: false, errores: ["Usuario y contraseña son obligatorios."] } };
  }

  const usuario = db.buscarUsuario(username);

  // Usuario inexistente: se gasta el mismo tiempo que en uno real.
  if (!usuario) {
    await hash.verificar(password, HASH_SENUELO);
    return { estado: 401, cuerpo: { ok: false, errores: [MENSAJE_CREDENCIALES] } };
  }

  // Cuenta bloqueada: ni siquiera se comprueba la contraseña. Si se comprobara,
  // el atacante podría seguir midiendo aciertos durante el bloqueo.
  if (db.estaBloqueada(usuario)) {
    return respuestaBloqueo(usuario);
  }

  const correcta = await hash.verificar(password, usuario.password_hash);

  if (!correcta) {
    const intentos = db.sumarIntentoFallido(usuario.id);
    if (intentos >= MAX_INTENTOS_CUENTA) {
      db.bloquearCuenta(usuario.id, MINUTOS_BLOQUEO);
      return respuestaBloqueo(db.buscarUsuarioPorId(usuario.id));
    }
    return {
      estado: 401,
      cuerpo: {
        ok: false,
        errores: [MENSAJE_CREDENCIALES],
        intentosRestantes: MAX_INTENTOS_CUENTA - intentos
      }
    };
  }

  // Login correcto: se borra el historial de fallos y se anota el acceso.
  db.desbloquearCuenta(usuario.id);
  db.registrarAcceso(usuario.id);

  return {
    estado: 200,
    cuerpo: { ok: true, username: usuario.username, rol: usuario.rol, mensaje: "Sesión iniciada." },
    usuario: { id: usuario.id, username: usuario.username, rol: usuario.rol }
  };
}

module.exports = { autenticar, MAX_INTENTOS_CUENTA, MINUTOS_BLOQUEO, MENSAJE_CREDENCIALES };
