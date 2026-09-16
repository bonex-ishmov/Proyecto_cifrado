/* ============================================================================
   validaciones.js — Reglas de entrada, ejecutadas SIEMPRE en el servidor
   Universidad El Bosque — Seguridad de la Información — 2026-II

   El formulario del navegador puede tener `required`, `minlength` y lo que sea,
   pero eso es comodidad para el usuario, no seguridad: cualquiera puede borrar
   esos atributos desde las herramientas del navegador o saltarse el formulario
   entero con curl. Estas funciones son la única validación que cuenta.

   Cada función devuelve un ARRAY de errores. Vacío significa que todo está bien.
   ============================================================================ */

/** Letras, números, punto, guion y guion bajo. Entre 3 y 50 caracteres. */
const PATRON_USERNAME = /^[A-Za-z0-9._-]{3,50}$/;

const LARGO_MINIMO_PASSWORD = 8;

/**
 * BCrypt solo considera los primeros 72 BYTES de la contraseña; lo que sobra se
 * descarta en silencio. Si no se valida, dos contraseñas larguísimas que
 * coincidan en sus primeros 72 bytes abrirían la misma cuenta. Se rechazan
 * explícitamente en vez de truncar sin avisar.
 */
const LIMITE_BYTES_BCRYPT = 72;

function validarUsername(username) {
  const errores = [];

  if (typeof username !== "string" || username.trim() === "") {
    errores.push("El nombre de usuario es obligatorio.");
    return errores;
  }
  // La columna username es VARCHAR(50) según el esquema de la guía.
  if (!PATRON_USERNAME.test(username)) {
    errores.push("El nombre de usuario debe tener entre 3 y 50 caracteres y solo puede " +
                 "contener letras, números, punto, guion y guion bajo.");
  }
  return errores;
}

function validarPassword(password, username = "") {
  const errores = [];

  if (typeof password !== "string" || password === "") {
    errores.push("La contraseña es obligatoria.");
    return errores;
  }
  if (password.length < LARGO_MINIMO_PASSWORD) {
    errores.push(`La contraseña debe tener al menos ${LARGO_MINIMO_PASSWORD} caracteres.`);
  }
  if (Buffer.byteLength(password, "utf8") > LIMITE_BYTES_BCRYPT) {
    errores.push(`La contraseña no puede superar ${LIMITE_BYTES_BCRYPT} bytes, que es el ` +
                 "máximo que procesa BCrypt. Ten en cuenta que las tildes y la ñ ocupan dos bytes.");
  }
  if (username && password.toLowerCase() === String(username).toLowerCase()) {
    errores.push("La contraseña no puede ser igual al nombre de usuario.");
  }
  return errores;
}

module.exports = {
  PATRON_USERNAME, LARGO_MINIMO_PASSWORD, LIMITE_BYTES_BCRYPT,
  validarUsername, validarPassword
};
