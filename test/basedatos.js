/* ============================================================================
   basedatos.js — Pruebas de la Fase 6
   Ejecutar con:  npm run test:bd

   Trabaja sobre una base temporal en disco que se borra al terminar, para no
   tocar datos/auth.db.
   ============================================================================ */

const fs = require("fs");
const os = require("os");
const path = require("path");

const RUTA_TEMPORAL = path.join(os.tmpdir(), `auth-prueba-${Date.now()}.db`);
process.env.DB_PATH = RUTA_TEMPORAL;

const db = require("../src/db.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}
function probarError(descripcion, fn, fragmento) {
  try { fn(); probar(descripcion, false); }
  catch (e) { probar(descripcion, e.message.includes(fragmento)); }
}

db.iniciar(RUTA_TEMPORAL);

/* --- Esquema ------------------------------------------------------------- */
console.log("\n=== Esquema ===");
const roles = db.listarRoles();
probar("Se crean los dos roles de la guía",
  roles.length === 2 && roles.some((r) => r.nombre === "Administrador") &&
  roles.some((r) => r.nombre === "Usuario"));

probar("Volver a aplicar el esquema no duplica los roles",
  (db.iniciar(RUTA_TEMPORAL), db.listarRoles().length === 2));

const columnas = db.conexion().prepare("PRAGMA table_info(usuarios)").all().map((c) => c.name);
probar("La tabla usuarios tiene todos los campos que exige la guía",
  ["id", "username", "password_hash", "rol_id", "intentos_fallidos", "bloqueado_hasta"]
    .every((c) => columnas.includes(c)));

probar("Las llaves foráneas están activas",
  db.conexion().prepare("PRAGMA foreign_keys").get().foreign_keys === 1);

/* --- Usuarios ------------------------------------------------------------ */
console.log("\n=== Usuarios ===");
const HASH_FALSO = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

const idAdmin = db.crearUsuario({ username: "admin", passwordHash: HASH_FALSO, rolNombre: "Administrador" });
const idUser = db.crearUsuario({ username: "manuela", passwordHash: HASH_FALSO, rolNombre: "Usuario" });
probar("Se crean usuarios y devuelven su id", idAdmin > 0 && idUser > idAdmin);

const admin = db.buscarUsuario("admin");
probar("La búsqueda trae el nombre del rol, no solo el id", admin.rol === "Administrador");
probar("El hash se guarda completo (60 caracteres de BCrypt)", admin.password_hash.length === 60);
probar("Un usuario nuevo arranca con 0 intentos fallidos y sin bloqueo",
  admin.intentos_fallidos === 0 && admin.bloqueado_hasta === null);

probarError("No se permiten nombres de usuario repetidos",
  () => db.crearUsuario({ username: "admin", passwordHash: HASH_FALSO, rolNombre: "Usuario" }),
  "ya está registrado");

probarError("No se permite asignar un rol inexistente",
  () => db.crearUsuario({ username: "otro", passwordHash: HASH_FALSO, rolNombre: "Superusuario" }),
  "no existe");

probar("Buscar un usuario inexistente devuelve undefined",
  db.buscarUsuario("fantasma") === undefined);

probar("El listado del panel NO expone los hashes",
  db.listarUsuarios().every((u) => u.password_hash === undefined));

probar("El listado trae los campos que necesita el panel",
  db.listarUsuarios().every((u) =>
    "intentos_fallidos" in u && "bloqueado_hasta" in u && "rol" in u));

/* --- Inyección SQL ------------------------------------------------------- */
console.log("\n=== Sentencias preparadas ===");
const MALICIOSO = "'; DROP TABLE usuarios; --";
probar("Un nombre de usuario malicioso no ejecuta SQL",
  (db.buscarUsuario(MALICIOSO) === undefined) && db.contarUsuarios() === 2);

/* --- Bloqueo por cuenta -------------------------------------------------- */
console.log("\n=== Bloqueo por cuenta ===");
probar("Cada fallo incrementa el contador",
  db.sumarIntentoFallido(idUser) === 1 && db.sumarIntentoFallido(idUser) === 2);

db.bloquearCuenta(idUser, 15);
probar("Una cuenta recién bloqueada figura como bloqueada",
  db.estaBloqueada(db.buscarUsuarioPorId(idUser)));
probar("Los segundos restantes son coherentes con 15 minutos",
  Math.abs(db.segundosDeBloqueo(db.buscarUsuarioPorId(idUser)) - 900) <= 2);

db.bloquearCuenta(idUser, -1);
probar("Un bloqueo ya vencido no cuenta como bloqueo",
  !db.estaBloqueada(db.buscarUsuarioPorId(idUser)) &&
  db.segundosDeBloqueo(db.buscarUsuarioPorId(idUser)) === 0);

db.desbloquearCuenta(idUser);
const desbloqueado = db.buscarUsuarioPorId(idUser);
probar("Desbloquear pone el contador en cero y quita la fecha",
  desbloqueado.intentos_fallidos === 0 && desbloqueado.bloqueado_hasta === null);

probar("Una cuenta sin bloqueo nunca figura como bloqueada",
  !db.estaBloqueada(db.buscarUsuarioPorId(idAdmin)));

/* --- Último acceso ------------------------------------------------------- */
console.log("\n=== Último acceso ===");
db.registrarAcceso(idAdmin);
const conAcceso = db.buscarUsuarioPorId(idAdmin);
probar("Se registra el último acceso con formato ISO",
  /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(conAcceso.ultimo_acceso));

/* --- Cierre -------------------------------------------------------------- */
db.cerrar();
fs.unlinkSync(RUTA_TEMPORAL);

console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
