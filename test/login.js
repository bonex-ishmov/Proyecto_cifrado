/* ============================================================================
   login.js — Pruebas de la Fase 8 (autenticación y bloqueo por cuenta)
   Ejecutar con:  npm run test:login
   ============================================================================ */

const fs = require("fs");
const os = require("os");
const path = require("path");

const RUTA_TEMPORAL = path.join(os.tmpdir(), `auth-fase8-${Date.now()}.db`);
process.env.DB_PATH = RUTA_TEMPORAL;

const db = require("../src/db.js");
const hash = require("../src/hash.js");
const { autenticar, MAX_INTENTOS_CUENTA, MENSAJE_CREDENCIALES } = require("../src/login.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

const CLAVE = "ClaveCorrecta123";
db.iniciar(RUTA_TEMPORAL);

async function principal() {
  const passwordHash = await hash.hashear(CLAVE);
  const id = db.crearUsuario({ username: "manuela", passwordHash, rolNombre: "Usuario" });
  db.crearUsuario({
    username: "admin",
    passwordHash: await hash.hashear("ClaveDelAdmin1"),
    rolNombre: "Administrador"
  });

/* --- Login correcto ------------------------------------------------------ */
console.log("\n=== Inicio de sesión correcto ===");
const bien = await autenticar({ username: "manuela", password: CLAVE });
probar("Responde 200", bien.estado === 200 && bien.cuerpo.ok === true);
probar("Devuelve el rol del usuario", bien.cuerpo.rol === "Usuario");
probar("Devuelve los datos mínimos para la sesión",
  bien.usuario.id === id && bien.usuario.username === "manuela" && bien.usuario.rol === "Usuario");
probar("La respuesta NUNCA incluye el hash de la contraseña",
  !JSON.stringify(bien).includes("$2"));
probar("Se registra el último acceso",
  typeof db.buscarUsuarioPorId(id).ultimo_acceso === "string");
probar("El administrador entra con su propio rol",
  (await autenticar({ username: "admin", password: "ClaveDelAdmin1" })).cuerpo.rol === "Administrador");

/* --- Credenciales incorrectas -------------------------------------------- */
console.log("\n=== Credenciales incorrectas ===");
const malaClave = await autenticar({ username: "manuela", password: "ClaveEquivocada1" });
const noExiste = await autenticar({ username: "fantasma", password: "ClaveEquivocada1" });

probar("Contraseña incorrecta responde 401", malaClave.estado === 401);
probar("Usuario inexistente responde 401", noExiste.estado === 401);
probar("Los dos casos dan EXACTAMENTE el mismo mensaje",
  malaClave.cuerpo.errores[0] === MENSAJE_CREDENCIALES &&
  noExiste.cuerpo.errores[0] === MENSAJE_CREDENCIALES);
probar("Un usuario inexistente no genera registros en la base", db.contarUsuarios() === 2);
probar("Faltando la contraseña responde 400",
  (await autenticar({ username: "manuela" })).estado === 400);
probar("Una petición vacía responde 400", (await autenticar({})).estado === 400);
probar("Tipos de datos inesperados no rompen el servidor",
  (await autenticar({ username: { $ne: null }, password: [1, 2] })).estado === 400);

/* --- Bloqueo por cuenta -------------------------------------------------- */
console.log(`\n=== Bloqueo por cuenta (máximo ${MAX_INTENTOS_CUENTA} intentos) ===`);
db.desbloquearCuenta(id);

const respuestas = [];
for (let i = 0; i < MAX_INTENTOS_CUENTA; i++) {
  respuestas.push(await autenticar({ username: "manuela", password: "ClaveEquivocada1" }));
}

probar(`Los primeros ${MAX_INTENTOS_CUENTA - 1} fallos responden 401`,
  respuestas.slice(0, -1).every((r) => r.estado === 401));
probar("El contador de intentos restantes va bajando",
  respuestas[0].cuerpo.intentosRestantes === MAX_INTENTOS_CUENTA - 1 &&
  respuestas[3].cuerpo.intentosRestantes === 1);
probar(`El fallo número ${MAX_INTENTOS_CUENTA} bloquea la cuenta (423)`,
  respuestas[MAX_INTENTOS_CUENTA - 1].estado === 423 &&
  respuestas[MAX_INTENTOS_CUENTA - 1].cuerpo.bloqueado === true);
probar("La respuesta de bloqueo informa los segundos restantes",
  respuestas[MAX_INTENTOS_CUENTA - 1].cuerpo.segundosRestantes > 0);
probar("El bloqueo quedó guardado en la base de datos",
  db.buscarUsuarioPorId(id).bloqueado_hasta !== null);

const conClaveBuena = await autenticar({ username: "manuela", password: CLAVE });
probar("Con la cuenta bloqueada, NI SIQUIERA la contraseña correcta entra",
  conClaveBuena.estado === 423);

const otroUsuario = await autenticar({ username: "admin", password: "ClaveDelAdmin1" });
probar("El bloqueo afecta solo a esa cuenta, no a las demás", otroUsuario.estado === 200);

/* --- Expiración del bloqueo ---------------------------------------------- */
console.log("\n=== Expiración del bloqueo ===");
db.bloquearCuenta(id, -1); // bloqueo con fecha ya vencida
const trasExpirar = await autenticar({ username: "manuela", password: CLAVE });
probar("Cuando el bloqueo vence, el usuario vuelve a entrar", trasExpirar.estado === 200);
probar("Entrar correctamente reinicia el contador y borra el bloqueo",
  db.buscarUsuarioPorId(id).intentos_fallidos === 0 &&
  db.buscarUsuarioPorId(id).bloqueado_hasta === null);

/* --- Un acierto a tiempo limpia el historial ----------------------------- */
console.log("\n=== Fallos no consecutivos ===");
await autenticar({ username: "manuela", password: "mal1mal1" });
await autenticar({ username: "manuela", password: "mal2mal2" });
await autenticar({ username: "manuela", password: CLAVE });
probar("Un inicio correcto borra los fallos anteriores",
  db.buscarUsuarioPorId(id).intentos_fallidos === 0);

for (let i = 0; i < 4; i++) await autenticar({ username: "manuela", password: "mal1mal1" });
probar("Tras el reinicio, hacen falta otra vez 5 fallos seguidos para bloquear",
  db.buscarUsuarioPorId(id).intentos_fallidos === 4 &&
  !db.estaBloqueada(db.buscarUsuarioPorId(id)));

/* --- Cierre -------------------------------------------------------------- */
db.cerrar();
fs.unlinkSync(RUTA_TEMPORAL);

console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
}

principal();
