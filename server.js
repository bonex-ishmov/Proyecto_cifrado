/* ============================================================================
   server.js  —  Servidor único del taller
   Universidad El Bosque — Seguridad de la Información — 2026-II

   El criptoanálisis sigue ocurriendo en el navegador (es cálculo, no una
   validación de seguridad). En cambio TODA la autenticación —registro, login,
   hashing y control de intentos— se procesa aquí, en el servidor, como exige la
   Nota Arquitectónica de la guía del módulo de inicio de sesión.

   Desarrollo:  node server.js  -> http://localhost:3000, sin certificado
   Producción:  con TLS_CERT y TLS_KEY definidas, HTTPS en el 443 y el puerto
                80 solo redirige a HTTPS (ver src/https.js)
   ============================================================================ */

const express = require("express");
const session = require("express-session");
const path = require("path");
const db = require("./src/db.js");
const { registrar } = require("./src/registro.js");
const { autenticar } = require("./src/login.js");
const { proteccionLogin } = require("./src/fuerzaBruta.js");
const { requiereSesion, requiereSesionPagina, requiereRol } = require("./src/autorizacion.js");
const { perfil, listadoUsuarios, desbloquearUsuario } = require("./src/panel.js");
const { configuracionTLS, arrancar } = require("./src/https.js");

const app = express();

/* Se lee al principio porque la cookie de sesión depende de ella. Si hay un
   certificado configurado pero no se puede leer, el servidor NO arranca: es
   preferible caído que sirviendo sin cifrado cuando se esperaba cifrado. */
let tls;
try {
  tls = configuracionTLS(process.env);
} catch (e) {
  console.error("Configuración de HTTPS inválida: " + e.message);
  process.exit(1);
}

/* La IP del cliente se toma de la conexión TCP, que no se puede falsificar.
   Como Node atiende HTTPS directamente, sin proxy delante, esa IP es la real.
   Si algún día se pone un proxy o un balanceador delante (nginx, un balanceador
   de AWS), habría que activar app.set("trust proxy", 1) para
   leer la IP real de la cabecera X-Forwarded-For. OJO: activarlo SIN proxy
   delante sería un agujero, porque cualquiera podría mandar esa cabecera a mano
   y estrenar una IP distinta en cada intento, saltándose el bloqueo. */

// Abre la base de datos y aplica el esquema si hace falta.
db.iniciar();

/* --- HSTS ------------------------------------------------------------------
   Con HTTPS activo, se le dice al navegador que durante un día no intente ni
   siquiera conectarse por HTTP a este dominio. La redirección del puerto 80
   protege la primera visita; HSTS protege las siguientes, porque el navegador
   ya ni pregunta por HTTP. Los navegadores ignoran esta cabecera si el
   certificado no es de confianza, así que con el autofirmado no tiene efecto.
--------------------------------------------------------------------------- */
if (tls) {
  app.use((req, res, next) => {
    res.set("Strict-Transport-Security", "max-age=86400");
    next();
  });
}

/* --- Middlewares generales ------------------------------------------------ */
// Leen el cuerpo de las peticiones. El límite evita que alguien intente
// tumbar el servidor mandando megabytes en un formulario de login.
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

/* --- Sesiones -------------------------------------------------------------
   El navegador solo guarda un identificador de sesión en una cookie; los datos
   del usuario viven en el servidor. El cliente nunca recibe su rol en forma
   manipulable: si la cookie dijera "rol=Administrador", bastaría con editarla.

   httpOnly: el JavaScript de la página no puede leer la cookie, lo que limita
             el daño de un XSS.
   sameSite: el navegador no envía la cookie en peticiones que vengan de otros
             sitios, que es la defensa básica contra CSRF.
   secure:   con HTTPS activo, la cookie solo viaja cifrada: el navegador se
             niega a mandarla por HTTP. Sin HTTPS (desarrollo) va en false,
             porque con true la sesión sencillamente no funcionaría.
--------------------------------------------------------------------------- */
app.use(session({
  name: "sid",
  secret: process.env.SESSION_SECRET || "clave-de-desarrollo-cambiar-en-produccion",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: Boolean(tls), maxAge: 30 * 60 * 1000 }
}));

/* --- Archivos del navegador ------------------------------------------------
   public/  se entrega a cualquiera: es lo que necesita ver quien todavía no ha
            iniciado sesión (login, registro y los estilos de ambos).
   privado/ se entrega SOLO con sesión: la herramienta de criptoanálisis y el
            panel. Sin cookie válida, el guardián redirige al login y el
            archivo nunca sale del servidor. Pedir /cripto.js a mano tampoco
            sirve: pasa por el mismo filtro.
--------------------------------------------------------------------------- */
app.use(express.static(path.join(__dirname, "public")));

/* --- Rutas de autenticación ----------------------------------------------- */
app.post("/registro", async (req, res, next) => {
  try {
    const { estado, cuerpo } = await registrar(req.body || {});
    res.status(estado).json(cuerpo);
  } catch (e) {
    next(e);
  }
});

app.post("/login", proteccionLogin.middleware, async (req, res, next) => {
  try {
    const { estado, cuerpo, usuario } = await autenticar(req.body || {});

    // Credenciales incorrectas: se suma el fallo al contador de la IP. Este es
    // el paso que le falta al ejemplo de la guía, sin el cual nunca se bloquea.
    if (!usuario) {
      const ip = proteccionLogin.registrarFallo(req);
      if (ip.bloqueado) {
        res.set("Retry-After", String(ip.segundosRestantes));
        return res.status(429).json({
          ok: false,
          bloqueadoPorIP: true,
          segundosRestantes: ip.segundosRestantes,
          errores: ["Demasiados intentos fallidos desde esta dirección. " +
                    `Inténtalo de nuevo en ${ip.segundosRestantes} segundos.`]
        });
      }
      return res.status(estado).json(cuerpo);
    }

    // Inicio de sesión correcto: la IP queda limpia.
    proteccionLogin.registrarExito(req);

    // Se genera una sesión NUEVA al iniciar sesión. Si se reutilizara la
    // anterior, un atacante podría fijar de antemano el identificador de
    // sesión de la víctima y heredar su sesión ya autenticada (session
    // fixation).
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.usuario = usuario;
      res.status(estado).json(cuerpo);
    });
  } catch (e) {
    next(e);
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("sid");
    res.json({ ok: true, mensaje: "Sesión cerrada." });
  });
});

// Quién está conectado. La usan las páginas para decidir qué mostrar.
app.get("/sesion", (req, res) => {
  if (req.session && req.session.usuario) {
    return res.json({ ok: true, usuario: req.session.usuario });
  }
  res.status(401).json({ ok: false, usuario: null });
});

/* --- Rutas protegidas ------------------------------------------------------
   El rol se comprueba en el servidor, contra req.session. Ocultar un botón en
   la página no protege nada: cualquiera puede llamar a estas rutas con curl.
--------------------------------------------------------------------------- */

// Cualquier usuario autenticado: sus propios datos.
app.get("/perfil", requiereSesion, (req, res) => {
  const { estado, cuerpo } = perfil(req.session.usuario);
  res.status(estado).json(cuerpo);
});

// Solo administradores: todas las cuentas y su estado de bloqueo.
app.get("/usuarios", requiereSesion, requiereRol("Administrador"), (req, res) => {
  const { estado, cuerpo } = listadoUsuarios();
  res.status(estado).json(cuerpo);
});

// Solo administradores: desbloquear una cuenta.
app.post("/usuarios/:id/desbloquear", requiereSesion, requiereRol("Administrador"), (req, res) => {
  const { estado, cuerpo } = desbloquearUsuario(req.params.id);
  res.status(estado).json(cuerpo);
});

// Solo administradores: foto del bloqueo por IP, que vive en memoria.
app.get("/bloqueos-ip", requiereSesion, requiereRol("Administrador"), (req, res) => {
  res.json({ ok: true, direcciones: proteccionLogin.estado() });
});

/* --- Páginas que exigen sesión --------------------------------------------
   Va DESPUÉS de todas las rutas. Si estuviera antes, interceptaría también
   POST /login y POST /registro, y nadie podría iniciar sesión.
--------------------------------------------------------------------------- */
app.use(requiereSesionPagina, express.static(path.join(__dirname, "privado")));

/* --- Manejador de errores -------------------------------------------------- */
// Se registra el detalle en el log del servidor, pero al cliente solo le llega
// un mensaje genérico: los mensajes de error detallados le dan pistas al
// atacante sobre la tecnología y la estructura interna.
app.use((err, req, res, next) => {
  console.error("Error no controlado:", err);
  res.status(500).json({ ok: false, errores: ["Error interno del servidor."] });
});

arrancar(app, tls);
