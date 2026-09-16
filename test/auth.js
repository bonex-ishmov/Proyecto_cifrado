/* ============================================================================
   auth.js — Pruebas de la Fase 7 (validaciones, BCrypt y registro)
   Ejecutar con:  npm run test:auth

   Requiere que bcryptjs esté instalado:  npm install
   ============================================================================ */

const fs = require("fs");
const os = require("os");
const path = require("path");

const RUTA_TEMPORAL = path.join(os.tmpdir(), `auth-fase7-${Date.now()}.db`);
process.env.DB_PATH = RUTA_TEMPORAL;

const db = require("../src/db.js");
const { validarUsername, validarPassword, LIMITE_BYTES_BCRYPT } = require("../src/validaciones.js");

let bcryptDisponible = true;
let hash, registro;
try {
  hash = require("../src/hash.js");
  registro = require("../src/registro.js");
} catch (e) {
  bcryptDisponible = false;
  console.error("\n  No se pudo cargar bcryptjs. Ejecuta `npm install` y vuelve a intentar.\n");
  process.exit(1);
}

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

db.iniciar(RUTA_TEMPORAL);

async function principal() {

/* --- Validaciones -------------------------------------------------------- */
console.log("\n=== Validaciones del servidor ===");
probar("Un usuario válido no produce errores", validarUsername("manuela.v").length === 0);
probar("Se rechaza un usuario de menos de 3 caracteres", validarUsername("ab").length > 0);
probar("Se rechaza un usuario con espacios", validarUsername("mi usuario").length > 0);
probar("Se rechaza un usuario con caracteres raros", validarUsername("admin'--").length > 0);
probar("Se rechaza un usuario de más de 50 caracteres (columna VARCHAR(50))",
  validarUsername("a".repeat(51)).length > 0);
probar("Se rechaza un usuario vacío o ausente",
  validarUsername("").length > 0 && validarUsername(undefined).length > 0);

probar("Una contraseña válida no produce errores", validarPassword("ClaveSegura123").length === 0);
probar("Se rechaza una contraseña de menos de 8 caracteres", validarPassword("corta1").length > 0);
probar("Se rechaza una contraseña igual al usuario (sin importar mayúsculas)",
  validarPassword("MiUsuario1", "miusuario1").length > 0);
probar(`Se rechaza una contraseña de más de ${LIMITE_BYTES_BCRYPT} bytes`,
  validarPassword("a".repeat(73)).length > 0);
probar("Las tildes y la ñ cuentan como dos bytes en el límite de BCrypt",
  validarPassword("ñ".repeat(37)).length > 0 && validarPassword("ñ".repeat(35)).length === 0);

/* --- BCrypt -------------------------------------------------------------- */
console.log("\n=== Hashing con BCrypt ===");
const CLAVE = "MiClaveDePrueba1";
const h1 = await hash.hashear(CLAVE);
const h2 = await hash.hashear(CLAVE);

probar("El hash tiene el formato de BCrypt", hash.esHashBcrypt(h1));
probar("El hash mide 60 caracteres", h1.length === 60);
probar(`El hash declara el factor de costo ${hash.COSTO}`, h1.startsWith(`$2`) && h1.slice(4, 6) === String(hash.COSTO));
probar("La misma contraseña genera hashes DISTINTOS (el salt es automático)", h1 !== h2);
probar("Aun así, los dos hashes verifican la misma contraseña",
  (await hash.verificar(CLAVE, h1)) && (await hash.verificar(CLAVE, h2)));
probar("La contraseña en claro no aparece dentro del hash", !h1.includes(CLAVE));
probar("Una contraseña incorrecta no verifica", !(await hash.verificar("otraClave123", h1)));
probar("Verificar contra basura devuelve false sin lanzar error",
  !(await hash.verificar(CLAVE, "no-es-un-hash")) && !(await hash.verificar(CLAVE, "")));

/* --- Registro ------------------------------------------------------------ */
console.log("\n=== Registro de usuarios ===");
const alta = await registro.registrar({ username: "manuela", password: "ClaveSegura123" });
probar("Un registro correcto responde 201", alta.estado === 201 && alta.cuerpo.ok === true);
probar("El usuario creado recibe el rol Usuario", alta.cuerpo.rol === "Usuario");

const guardado = db.buscarUsuario("manuela");
probar("En la base NO queda la contraseña en claro",
  guardado.password_hash !== "ClaveSegura123" && hash.esHashBcrypt(guardado.password_hash));
probar("La contraseña guardada verifica correctamente",
  await hash.verificar("ClaveSegura123", guardado.password_hash));

const conRol = await registro.registrar({
  username: "intruso", password: "ClaveSegura123", rol: "Administrador", rol_id: 1
});
probar("Pedir el rol Administrador en la petición NO sirve de nada",
  conRol.cuerpo.ok === true && db.buscarUsuario("intruso").rol === "Usuario");

const repetido = await registro.registrar({ username: "manuela", password: "OtraClave123" });
probar("Un usuario repetido responde 409", repetido.estado === 409 && repetido.cuerpo.ok === false);

const invalido = await registro.registrar({ username: "ab", password: "123" });
probar("Datos inválidos responden 400 con la lista de errores",
  invalido.estado === 400 && invalido.cuerpo.errores.length >= 2);

const vacio = await registro.registrar({});
probar("Una petición vacía no rompe el servidor", vacio.estado === 400);

const raro = await registro.registrar({ username: { $ne: null }, password: ["array"] });
probar("Tipos de datos inesperados se rechazan sin lanzar excepción", raro.estado === 400);

probar("Los registros inválidos no crearon usuarios", db.contarUsuarios() === 2);

probar("El espacio sobrante del nombre de usuario se recorta",
  (await registro.registrar({ username: "  espacios  ", password: "ClaveSegura123" })).cuerpo.username === "espacios");

/* --- Cierre -------------------------------------------------------------- */
db.cerrar();
fs.unlinkSync(RUTA_TEMPORAL);

console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
}

principal();
