/* ============================================================================
   hash.js — Hashing de contraseñas con BCrypt
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Se usa `bcryptjs` y no `bcrypt`. Los dos implementan el mismo algoritmo y
   producen hashes intercambiables; la diferencia es que `bcrypt` es un módulo
   nativo que debe compilarse con node-gyp al instalarlo, cosa que en una
   instancia EC2 t3.micro (1 GB de RAM) falla o tarda muchísimo. `bcryptjs` es
   JavaScript puro: se instala sin compilar nada. A cambio es más lento, lo que
   aquí no importa.

   Todo el archivo existe para que el resto del proyecto no dependa
   directamente de la librería: si algún día se cambia, solo se toca este
   archivo.
   ============================================================================ */

const bcrypt = require("bcryptjs");

/**
 * Factor de costo (work factor). El hash resultante incluye 2^COSTO rondas,
 * así que subirlo encarece el ataque por fuerza bruta y también el login
 * legítimo. 10 es el valor que recomienda la guía del laboratorio.
 */
const COSTO = 10;

/** Genera el hash. El salt lo crea y lo embebe BCrypt automáticamente. */
async function hashear(password) {
  return bcrypt.hash(password, COSTO);
}

/**
 * Compara una contraseña en claro contra un hash almacenado. BCrypt extrae el
 * salt y el costo del propio hash, así que no hay que guardarlos aparte.
 */
async function verificar(password, hashAlmacenado) {
  if (typeof password !== "string" || typeof hashAlmacenado !== "string" || hashAlmacenado === "") {
    return false;
  }
  try {
    return await bcrypt.compare(password, hashAlmacenado);
  } catch (e) {
    // Un hash corrupto en la base no debe tumbar el login: se trata como
    // credencial incorrecta y se deja constancia en el log del servidor.
    console.error("Hash inválido al verificar una contraseña:", e.message);
    return false;
  }
}

/**
 * ¿La cadena tiene la forma de un hash BCrypt?
 *   $2b$ 10 $ [22 chars de salt][31 chars de hash]   =  60 caracteres
 * Sirve para comprobar en las pruebas que en la base nunca quede una
 * contraseña en claro por accidente.
 */
function esHashBcrypt(cadena) {
  return typeof cadena === "string" && /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(cadena);
}

module.exports = { COSTO, hashear, verificar, esHashBcrypt };
