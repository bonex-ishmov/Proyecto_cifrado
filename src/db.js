/* ============================================================================
   db.js — Acceso a la base de datos
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Único archivo que habla SQL. El resto del servidor llama a estas funciones y
   nunca escribe consultas, para que toda la interacción con la base esté en un
   solo lugar auditable.

   Motor: módulo `node:sqlite`, integrado en Node 22. No requiere instalar nada
   ni compilar código nativo, que es justo lo que se quiere en una instancia
   EC2 pequeña. Node lo marca como experimental e imprime un aviso al arrancar.

   SEGURIDAD: todas las consultas usan sentencias preparadas con parámetros (?).
   Nunca se concatena texto del usuario dentro del SQL; eso es lo que evita la
   inyección SQL.
   ============================================================================ */

const { DatabaseSync } = require("node:sqlite");
const fs = require("fs");
const path = require("path");

const RAIZ = path.join(__dirname, "..");
const RUTA_BD = process.env.DB_PATH || path.join(RAIZ, "datos", "auth.db");
const RUTA_ESQUEMA = path.join(RAIZ, "sql", "esquema.sql");

let bd = null;

/* ---------------------------------------------------------------------------
   Apertura e inicialización
--------------------------------------------------------------------------- */

/**
 * Abre la base de datos y aplica el esquema. Es idempotente: el script usa
 * CREATE TABLE IF NOT EXISTS, así que se puede llamar en cada arranque.
 */
function iniciar(rutaBD = RUTA_BD) {
  if (rutaBD !== ":memory:") {
    fs.mkdirSync(path.dirname(rutaBD), { recursive: true });
  }
  bd = new DatabaseSync(rutaBD);
  bd.exec("PRAGMA foreign_keys = ON;");
  bd.exec(fs.readFileSync(RUTA_ESQUEMA, "utf8"));
  return bd;
}

function cerrar() {
  if (bd) { bd.close(); bd = null; }
}

/** Devuelve la conexión, abriéndola si hace falta. */
function conexion() {
  if (!bd) iniciar();
  return bd;
}

/** Fecha y hora actual en UTC, con el formato que guarda la base. */
function ahoraISO(desplazamientoMs = 0) {
  return new Date(Date.now() + desplazamientoMs)
    .toISOString().replace("T", " ").slice(0, 19);
}

/* ---------------------------------------------------------------------------
   Roles
--------------------------------------------------------------------------- */
function obtenerRol(nombre) {
  return conexion().prepare("SELECT * FROM roles WHERE nombre = ?").get(nombre);
}

function listarRoles() {
  return conexion().prepare("SELECT * FROM roles ORDER BY id").all();
}

/* ---------------------------------------------------------------------------
   Usuarios
--------------------------------------------------------------------------- */

/**
 * Crea un usuario. El hash llega ya calculado: esta capa no sabe nada de
 * BCrypt, solo lo guarda.
 * @throws Error si el nombre de usuario ya existe o el rol no existe.
 */
function crearUsuario({ username, passwordHash, rolNombre }) {
  const rol = obtenerRol(rolNombre);
  if (!rol) throw new Error(`El rol "${rolNombre}" no existe.`);

  try {
    const r = conexion()
      .prepare("INSERT INTO usuarios (username, password_hash, rol_id) VALUES (?, ?, ?)")
      .run(username, passwordHash, rol.id);
    return Number(r.lastInsertRowid);
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      throw new Error("Ese nombre de usuario ya está registrado.");
    }
    throw e;
  }
}

/** Busca por nombre de usuario, incluyendo el nombre del rol. Undefined si no existe. */
function buscarUsuario(username) {
  return conexion().prepare(`
    SELECT u.*, r.nombre AS rol
    FROM usuarios u JOIN roles r ON r.id = u.rol_id
    WHERE u.username = ?
  `).get(username);
}

function buscarUsuarioPorId(id) {
  return conexion().prepare(`
    SELECT u.*, r.nombre AS rol
    FROM usuarios u JOIN roles r ON r.id = u.rol_id
    WHERE u.id = ?
  `).get(id);
}

/** Lista para el panel del administrador. No devuelve los hashes. */
function listarUsuarios() {
  return conexion().prepare(`
    SELECT u.id, u.username, r.nombre AS rol,
           u.intentos_fallidos, u.bloqueado_hasta, u.ultimo_acceso
    FROM usuarios u JOIN roles r ON r.id = u.rol_id
    ORDER BY u.id
  `).all();
}

function contarUsuarios() {
  return conexion().prepare("SELECT COUNT(*) AS n FROM usuarios").get().n;
}

/* ---------------------------------------------------------------------------
   Bloqueo por cuenta
   (el bloqueo por IP vive en src/fuerzaBruta.js y no toca la base de datos)
--------------------------------------------------------------------------- */

/** Suma un fallo y devuelve el total acumulado. */
function sumarIntentoFallido(id) {
  conexion()
    .prepare("UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE id = ?")
    .run(id);
  return buscarUsuarioPorId(id).intentos_fallidos;
}

/** Bloquea la cuenta durante los minutos indicados. */
function bloquearCuenta(id, minutos) {
  const hasta = ahoraISO(minutos * 60 * 1000);
  conexion().prepare("UPDATE usuarios SET bloqueado_hasta = ? WHERE id = ?").run(hasta, id);
  return hasta;
}

/** Quita el bloqueo y pone el contador en cero (login correcto o desbloqueo manual). */
function desbloquearCuenta(id) {
  conexion()
    .prepare("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?")
    .run(id);
}

/**
 * ¿La cuenta está bloqueada en este momento?
 * Las fechas se guardan como texto ISO en UTC, así que la comparación de
 * cadenas equivale a la comparación cronológica.
 */
function estaBloqueada(usuario) {
  if (!usuario || !usuario.bloqueado_hasta) return false;
  return usuario.bloqueado_hasta > ahoraISO();
}

/** Segundos que faltan para que expire el bloqueo. 0 si no está bloqueada. */
function segundosDeBloqueo(usuario) {
  if (!estaBloqueada(usuario)) return 0;
  const fin = new Date(usuario.bloqueado_hasta.replace(" ", "T") + "Z").getTime();
  return Math.max(0, Math.ceil((fin - Date.now()) / 1000));
}

function registrarAcceso(id) {
  conexion().prepare("UPDATE usuarios SET ultimo_acceso = ? WHERE id = ?").run(ahoraISO(), id);
}

/* --------------------------------------------------------------------------- */
module.exports = {
  iniciar, cerrar, conexion, ahoraISO,
  obtenerRol, listarRoles,
  crearUsuario, buscarUsuario, buscarUsuarioPorId, listarUsuarios, contarUsuarios,
  sumarIntentoFallido, bloquearCuenta, desbloquearCuenta,
  estaBloqueada, segundosDeBloqueo, registrarAcceso
};
