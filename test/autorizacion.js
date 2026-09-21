/* ============================================================================
   autorizacion.js — Pruebas de la Fase 10 (control de acceso y paneles)
   Ejecutar con:  npm run test:roles
   ============================================================================ */

const fs = require("fs");
const os = require("os");
const path = require("path");

const RUTA_TEMPORAL = path.join(os.tmpdir(), `auth-fase10-${Date.now()}.db`);
process.env.DB_PATH = RUTA_TEMPORAL;

const db = require("../src/db.js");
const hash = require("../src/hash.js");
const { requiereSesion, requiereSesionPagina, requiereRol } = require("../src/autorizacion.js");
const { perfil, listadoUsuarios, desbloquearUsuario } = require("../src/panel.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- Dobles de req y res -------------------------------------------------- */
function respuesta() {
  const r = {
    codigo: null, cuerpo: null,
    status(c) { r.codigo = c; return r; },
    json(cuerpo) { r.cuerpo = cuerpo; return r; }
  };
  return r;
}

/** Ejecuta un middleware y reporta si dejó pasar y con qué respondió. */
function ejecutar(middleware, sesion) {
  const req = sesion === null ? {} : { session: { usuario: sesion } };
  const res = respuesta();
  let siguio = false;
  middleware(req, res, () => { siguio = true; });
  return { siguio, codigo: res.codigo, cuerpo: res.cuerpo };
}

const ADMIN = { id: 1, username: "admin", rol: "Administrador" };
const USUARIO = { id: 2, username: "manuela", rol: "Usuario" };

db.iniciar(RUTA_TEMPORAL);

async function principal() {
  db.crearUsuario({ username: "admin", passwordHash: await hash.hashear("ClaveDelAdmin1"), rolNombre: "Administrador" });
  db.crearUsuario({ username: "manuela", passwordHash: await hash.hashear("ClaveSegura123"), rolNombre: "Usuario" });

/* --- requiereSesion ------------------------------------------------------ */
console.log("\n=== Middleware requiereSesion ===");
probar("Sin sesión responde 401 y corta la petición",
  ejecutar(requiereSesion, null).codigo === 401 && !ejecutar(requiereSesion, null).siguio);
probar("Con sesión deja pasar", ejecutar(requiereSesion, USUARIO).siguio === true);
probar("Una petición sin objeto session no rompe nada",
  (() => { const res = respuesta(); let s = false;
           requiereSesion({}, res, () => { s = true; }); return res.codigo === 401 && !s; })());

/* --- requiereRol --------------------------------------------------------- */
console.log("\n=== Middleware requiereRol ===");
const soloAdmin = requiereRol("Administrador");

probar("Un administrador pasa", ejecutar(soloAdmin, ADMIN).siguio === true);
probar("Un usuario normal recibe 403 Forbidden",
  ejecutar(soloAdmin, USUARIO).codigo === 403 && !ejecutar(soloAdmin, USUARIO).siguio);
probar("Sin sesión recibe 401, no 403", ejecutar(soloAdmin, null).codigo === 401);
probar("La comprobación distingue 401 (no sé quién eres) de 403 (sé quién eres y no puedes)",
  ejecutar(soloAdmin, null).codigo !== ejecutar(soloAdmin, USUARIO).codigo);
probar("Un rol inventado en la sesión no abre la puerta",
  ejecutar(soloAdmin, { id: 9, username: "x", rol: "Superadministrador" }).codigo === 403);
probar("requiereRol admite varios roles a la vez",
  ejecutar(requiereRol("Administrador", "Usuario"), USUARIO).siguio === true);

/* --- requiereSesionPagina ------------------------------------------------- */
console.log("\n=== Middleware requiereSesionPagina (archivos del navegador) ===");
function ejecutarPagina(sesion, method = "GET") {
  const req = sesion === null ? { method } : { method, session: { usuario: sesion } };
  let destino = null, siguio = false;
  const res = { redirect(d) { destino = d; } };
  requiereSesionPagina(req, res, () => { siguio = true; });
  return { destino, siguio };
}
probar("Sin sesión redirige al login en vez de devolver un JSON",
  ejecutarPagina(null).destino === "/login.html" && !ejecutarPagina(null).siguio);
probar("Con sesión entrega la página", ejecutarPagina(USUARIO).siguio === true);
probar("El administrador también entra a las páginas comunes",
  ejecutarPagina(ADMIN).siguio === true);
probar("Sin sesión, un POST pasa de largo (si no, POST /login sería inalcanzable)",
  ejecutarPagina(null, "POST").siguio === true && ejecutarPagina(null, "POST").destino === null);
probar("Sin sesión, HEAD también se protege",
  ejecutarPagina(null, "HEAD").destino === "/login.html");

/* --- El rol NO se lee de la petición ------------------------------------- */
console.log("\n=== El rol solo se lee de la sesión del servidor ===");
const reqFalsificada = {
  session: { usuario: USUARIO },      // lo que el servidor sabe
  body: { rol: "Administrador" },     // lo que el atacante manda
  query: { rol: "Administrador" },
  headers: { "x-rol": "Administrador" }
};
const resFalsificada = respuesta();
let paso = false;
soloAdmin(reqFalsificada, resFalsificada, () => { paso = true; });
probar("Mandar rol=Administrador en el cuerpo, la query o una cabecera no sirve de nada",
  paso === false && resFalsificada.codigo === 403);

/* --- Panel del usuario --------------------------------------------------- */
console.log("\n=== Panel del usuario ===");
const miPerfil = perfil(USUARIO);
probar("Devuelve los datos del usuario de la sesión",
  miPerfil.estado === 200 && miPerfil.cuerpo.perfil.username === "manuela");
probar("El perfil NO incluye el hash de la contraseña",
  !JSON.stringify(miPerfil).includes("$2"));
probar("Una sesión que apunta a una cuenta borrada responde 401",
  perfil({ id: 999, username: "fantasma", rol: "Usuario" }).estado === 401);

/* --- Panel del administrador --------------------------------------------- */
console.log("\n=== Panel del administrador ===");
const listado = listadoUsuarios();
probar("Lista todas las cuentas", listado.cuerpo.usuarios.length === 2);
probar("El listado NO expone hashes",
  listado.cuerpo.usuarios.every((u) => u.password_hash === undefined));
probar("Cada cuenta trae el estado de bloqueo ya calculado",
  listado.cuerpo.usuarios.every((u) => "bloqueada" in u && "segundosRestantes" in u));

const idManuela = db.buscarUsuario("manuela").id;
db.sumarIntentoFallido(idManuela);
db.bloquearCuenta(idManuela, 15);
probar("Una cuenta bloqueada aparece como bloqueada en el listado",
  listadoUsuarios().cuerpo.usuarios.find((u) => u.id === idManuela).bloqueada === true);

const desbloqueo = desbloquearUsuario(idManuela);
probar("Desbloquear responde 200 con mensaje",
  desbloqueo.estado === 200 && desbloqueo.cuerpo.mensaje.includes("manuela"));
probar("Tras desbloquear, la cuenta queda activa y sin fallos",
  db.buscarUsuarioPorId(idManuela).intentos_fallidos === 0 &&
  !db.estaBloqueada(db.buscarUsuarioPorId(idManuela)));

probar("Desbloquear un usuario inexistente responde 404",
  desbloquearUsuario(9999).estado === 404);
probar("Un identificador inválido responde 400",
  desbloquearUsuario("abc").estado === 400 && desbloquearUsuario(-1).estado === 400);
probar("Un identificador con inyección responde 400 sin tocar la base",
  desbloquearUsuario("1 OR 1=1").estado === 400 && db.contarUsuarios() === 2);

/* --- Cierre -------------------------------------------------------------- */
db.cerrar();
fs.unlinkSync(RUTA_TEMPORAL);

console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
}

principal();
