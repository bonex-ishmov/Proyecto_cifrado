#!/usr/bin/env node
/* ============================================================================
   crear-admin.js — Crea un usuario con rol Administrador
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Uso:   node scripts/crear-admin.js [nombre_de_usuario]

   El registro de la página web solo crea usuarios con rol 'Usuario'. El primer
   administrador tiene que crearse desde la consola del servidor, que es el
   único sitio donde ya se confía en quien ejecuta el comando: si tienes acceso
   SSH a la máquina, podrías modificar la base de todas formas.

   La contraseña se pide por teclado y NO se pasa como argumento a propósito:
   los argumentos quedan guardados en el historial del shell (~/.bash_history) y
   son visibles para cualquier usuario del sistema con `ps aux`.
   ============================================================================ */

const readline = require("readline");
const db = require("../src/db.js");
const { hashear, esHashBcrypt } = require("../src/hash.js");
const { validarUsername, validarPassword } = require("../src/validaciones.js");

const ROL = "Administrador";

function preguntar(rl, texto) {
  return new Promise((resolve) => rl.question(texto, (respuesta) => resolve(respuesta)));
}

async function principal() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  try {
    db.iniciar();

    const username = (process.argv[2] || await preguntar(rl, "Nombre de usuario: ")).trim();
    const erroresUsuario = validarUsername(username);
    if (erroresUsuario.length) {
      erroresUsuario.forEach((e) => console.error("  " + e));
      process.exitCode = 1;
      return;
    }

    if (db.buscarUsuario(username)) {
      console.error(`  El usuario "${username}" ya existe.`);
      process.exitCode = 1;
      return;
    }

    console.log("\n  Aviso: la contraseña se verá en pantalla mientras la escribes.\n");
    const password = await preguntar(rl, "Contraseña: ");
    const confirmacion = await preguntar(rl, "Repite la contraseña: ");

    const erroresPassword = validarPassword(password, username);
    if (erroresPassword.length) {
      erroresPassword.forEach((e) => console.error("  " + e));
      process.exitCode = 1;
      return;
    }
    if (password !== confirmacion) {
      console.error("  Las contraseñas no coinciden.");
      process.exitCode = 1;
      return;
    }

    const passwordHash = await hashear(password);
    if (!esHashBcrypt(passwordHash)) {
      console.error("  El hash generado no tiene el formato de BCrypt. Revisa la instalación.");
      process.exitCode = 1;
      return;
    }

    const id = db.crearUsuario({ username, passwordHash, rolNombre: ROL });
    console.log(`\n  Administrador creado: id ${id}, usuario "${username}".`);
    console.log(`  Hash almacenado: ${passwordHash.slice(0, 29)}...\n`);
  } finally {
    rl.close();
    db.cerrar();
  }
}

principal().catch((e) => {
  console.error("  Error: " + e.message);
  process.exit(1);
});
