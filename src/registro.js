/* ============================================================================
   registro.js — Alta de usuarios
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Devuelve { estado, cuerpo } en vez de escribir la respuesta HTTP. Así la
   lógica se puede probar sin levantar el servidor, y server.js queda con una
   sola línea por ruta.

   REGLA DE SEGURIDAD CENTRAL: el registro público SIEMPRE crea el rol
   'Usuario'. El campo rol que llegue en la petición se ignora por completo. Si
   se aceptara, cualquiera podría registrarse como Administrador con una
   petición hecha a mano y el control de acceso por roles no valdría nada.
   El primer administrador se crea desde la consola del servidor con
   scripts/crear-admin.js.
   ============================================================================ */

const db = require("./db.js");
const { hashear } = require("./hash.js");
const { validarUsername, validarPassword } = require("./validaciones.js");

const ROL_REGISTRO_PUBLICO = "Usuario";

async function registrar(datos = {}) {
  const username = typeof datos.username === "string" ? datos.username.trim() : datos.username;
  const password = datos.password;

  const errores = [...validarUsername(username), ...validarPassword(password, username)];
  if (errores.length > 0) {
    return { estado: 400, cuerpo: { ok: false, errores } };
  }

  let passwordHash;
  try {
    passwordHash = await hashear(password);
  } catch (e) {
    // Si BCrypt falla, el problema es del servidor, no del usuario.
    return { estado: 500, cuerpo: { ok: false, errores: ["No se pudo procesar la contraseña."] } };
  }

  try {
    const id = db.crearUsuario({ username, passwordHash, rolNombre: ROL_REGISTRO_PUBLICO });
    return {
      estado: 201,
      cuerpo: {
        ok: true,
        id,
        username,
        rol: ROL_REGISTRO_PUBLICO,
        mensaje: "Cuenta creada. Ya puedes iniciar sesión."
      }
    };
  } catch (e) {
    if (e.message.includes("ya está registrado")) {
      return { estado: 409, cuerpo: { ok: false, errores: [e.message] } };
    }
    throw e;
  }
}

module.exports = { registrar, ROL_REGISTRO_PUBLICO };
