-- ============================================================================
-- esquema.sql — Estructura de la base de datos de autenticación
-- Universidad El Bosque — Seguridad de la Información — 2026-II
-- Motor: SQLite 3
--
-- Equivale campo por campo a la tabla de la guía de laboratorio, con dos
-- traducciones obligadas por el motor:
--   · AUTO_INCREMENT (MySQL)  ->  INTEGER PRIMARY KEY AUTOINCREMENT (SQLite)
--   · DATETIME (MySQL)        ->  TEXT con fecha ISO en UTC (SQLite no tiene
--                                 tipo de fecha; el texto ISO se ordena y
--                                 compara correctamente como cadena)
--
-- Se ejecuta solo con:  sqlite3 datos/auth.db < sql/esquema.sql
-- o automáticamente al arrancar el servidor, desde src/db.js
-- ============================================================================

-- SQLite NO valida las llaves foráneas si no se activa explícitamente.
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------------
-- Tabla roles
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre  TEXT    NOT NULL UNIQUE
);

-- ----------------------------------------------------------------------------
-- Tabla usuarios
--   password_hash     cadena completa de BCrypt ($2b$10$salt+hash, 60 chars)
--   intentos_fallidos contador de fallos consecutivos de inicio de sesión
--   bloqueado_hasta   momento en que termina el bloqueo temporal de la cuenta;
--                     NULL significa que la cuenta no está bloqueada
--   ultimo_acceso     último inicio de sesión correcto (lo muestra el panel)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  username           TEXT    NOT NULL UNIQUE,
  password_hash      TEXT    NOT NULL,
  rol_id             INTEGER NOT NULL,
  intentos_fallidos  INTEGER NOT NULL DEFAULT 0,
  bloqueado_hasta    TEXT    NULL,
  ultimo_acceso      TEXT    NULL,
  FOREIGN KEY (rol_id) REFERENCES roles(id)
);

-- Búsqueda por nombre de usuario en cada intento de login.
CREATE INDEX IF NOT EXISTS idx_usuarios_username ON usuarios(username);

-- ----------------------------------------------------------------------------
-- Datos iniciales
-- INSERT OR IGNORE evita el error de clave duplicada si el script se ejecuta
-- más de una vez, cosa que ocurre en cada arranque del servidor.
-- ----------------------------------------------------------------------------
INSERT OR IGNORE INTO roles (nombre) VALUES ('Administrador');
INSERT OR IGNORE INTO roles (nombre) VALUES ('Usuario');
