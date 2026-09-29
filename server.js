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
const captcha = require("./src/captcha.js");
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

/* --- Modo de prueba del CAPTCHA -------------------------------------------
   test/servidor.js recorre el flujo completo por HTTP, y un CAPTCHA que
   funcione no lo puede resolver un programa: ese es justamente su trabajo. Con
   CAPTCHA_PRUEBA definida, el desafío se genera siempre de tipo "texto" y con
   una respuesta conocida, de modo que la prueba de humo pueda comprobar el
   cableado entero (que es para lo que existe) sin desactivar nada.

   Para que eso no se convierta en una puerta trasera, la variable y un
   certificado configurado son incompatibles: en producción SIEMPRE hay
   TLS_CERT y TLS_KEY, así que el servidor sencillamente no arranca. Es la
   misma regla del resto del proyecto: un error de configuración detiene el
   arranque, no se degrada en silencio.
--------------------------------------------------------------------------- */
const CAPTCHA_PRUEBA = process.env.CAPTCHA_PRUEBA || "";
if (CAPTCHA_PRUEBA && tls) {
  console.error("CAPTCHA_PRUEBA está definida y hay un certificado configurado. " +
                "Ese modo es solo para las pruebas automáticas: no arranco.");
  process.exit(1);
}
if (CAPTCHA_PRUEBA) {
  console.log("AVISO: CAPTCHA en modo de prueba, con respuesta fija. Solo para test/servidor.js.");
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

    /* Credenciales correctas, pero la sesión TODAVÍA NO se abre: falta el
       CAPTCHA. Lo que se guarda es un inicio de sesión "pendiente", que no
       sirve para nada por sí mismo: requiereSesion y requiereSesionPagina
       miran req.session.usuario, que sigue vacío.

       El contador de la IP se limpia al final del todo, en POST /captcha, no
       aquí: mientras el paso intermedio no se supere, el inicio de sesión no
       ha terminado. */

    /* La sesión se renueva AQUÍ, no al superar el CAPTCHA, y el motivo merece
       explicarse porque es el punto delicado de este diseño:

       Si un atacante consigue fijar de antemano el identificador de sesión de
       la víctima (session fixation) y la renovación se hiciera al final, el
       "pendiente" quedaría escrito en una sesión cuyo identificador el
       atacante conoce. Le bastaría entonces con resolver él mismo un CAPTCHA
       —es una persona, lo resuelve sin esfuerzo— para quedarse con la sesión
       de la víctima. Renovando al guardar el pendiente, el identificador que
       el atacante plantó muere antes de que exista nada que robar. */
    req.session.regenerate((err) => {
      if (err) return next(err);

      req.session.pendiente = {
        id: usuario.id, username: usuario.username, rol: usuario.rol,
        creado: Date.now()
      };
      req.session.captcha = nuevoDesafio();
      req.session.intentosCaptcha = captcha.INTENTOS;

      res.status(200).json({
        ok: true,
        autenticado: false,
        requiereCaptcha: true,
        siguiente: "/captcha.html",
        mensaje: "Credenciales correctas. Falta comprobar que eres una persona."
      });
    });
  } catch (e) {
    next(e);
  }
});

/* --- Verificación humana (CAPTCHA) -----------------------------------------
   Paso intermedio entre "la contraseña es correcta" y "hay sesión". Ver
   src/captcha.js para qué defiende y qué no.

   El desafío entero, dibujo incluido, se guarda en req.session, que vive en la
   memoria del servidor. Son unos 7 KB por inicio de sesión a medias, y caducan
   a los CAPTCHA.MINUTOS_VIGENCIA minutos. La alternativa sería guardar solo la
   respuesta y volver a dibujar en cada petición; con un servidor único no
   compensa la complicación.
--------------------------------------------------------------------------- */

/** Crea un desafío nuevo, respetando el modo de prueba si está activo. */
function nuevoDesafio(tipo) {
  if (CAPTCHA_PRUEBA) {
    const desafio = captcha.crearDesafio("texto");
    desafio.respuesta = captcha.normalizar("texto", CAPTCHA_PRUEBA);
    return desafio;
  }
  return captcha.crearDesafio(tipo);
}

/** Devuelve el inicio de sesión pendiente si existe, tiene desafío y no caducó. */
function pendienteVigente(req) {
  const pendiente = req.session && req.session.pendiente;
  // Se exige también el desafío: las dos cosas se guardan y se borran juntas,
  // así que si falta una, la sesión está a medio escribir y no es de fiar.
  if (!pendiente || !req.session.captcha) return null;
  if (Date.now() - pendiente.creado > captcha.MINUTOS_VIGENCIA * 60 * 1000) return null;
  return pendiente;
}

/** Tira el inicio de sesión a medias. Obliga a volver a escribir la contraseña. */
function descartarPendiente(req) {
  if (!req.session) return;
  delete req.session.pendiente;
  delete req.session.captcha;
  delete req.session.intentosCaptcha;
}

const SIN_PENDIENTE = {
  ok: false,
  reiniciar: true,
  errores: ["No hay un inicio de sesión en curso, o ya caducó. " +
            "Vuelve a introducir tus credenciales."]
};

// Entrega el desafío actual. Recargar la página NO gasta intentos; pedir otra
// imagen a propósito (?otra=1) sí, porque si no, un programa podría pedir
// imágenes hasta que le saliera una cómoda de resolver.
app.get("/captcha", (req, res) => {
  if (!pendienteVigente(req)) {
    descartarPendiente(req);
    return res.status(401).json(SIN_PENDIENTE);
  }

  if (req.query.otra === "1") {
    req.session.intentosCaptcha -= 1;
    if (req.session.intentosCaptcha <= 0) {
      descartarPendiente(req);
      return res.status(401).json(SIN_PENDIENTE);
    }
    // Del MISMO tipo: si cambiara, bastaría con insistir hasta que saliera la
    // variante más fácil de automatizar.
    req.session.captcha = nuevoDesafio(req.session.captcha.tipo);
  }

  res.json({
    ok: true,
    usuario: req.session.pendiente.username,
    intentosRestantes: req.session.intentosCaptcha,
    desafio: captcha.parteMostrable(req.session.captcha)
  });
});

// Comprueba la respuesta. Solo aquí se abre la sesión de verdad.
app.post("/captcha", (req, res) => {
  const pendiente = pendienteVigente(req);
  if (!pendiente) {
    descartarPendiente(req);
    return res.status(401).json(SIN_PENDIENTE);
  }

  // La comparación ocurre en el servidor, contra lo guardado en la sesión. La
  // respuesta correcta no ha viajado nunca al navegador: si viajara, daría
  // igual lo bien dibujado que estuviera el desafío.
  if (!captcha.verificar(req.session.captcha, (req.body || {}).respuesta)) {
    req.session.intentosCaptcha -= 1;

    if (req.session.intentosCaptcha <= 0) {
      descartarPendiente(req);
      return res.status(401).json({
        ok: false,
        reiniciar: true,
        errores: ["Demasiados fallos en la comprobación. Vuelve a introducir tus credenciales."]
      });
    }

    // Nunca se repite el mismo desafío: si se repitiera, se podría ir
    // probando respuestas contra una imagen fija hasta acertar.
    req.session.captcha = nuevoDesafio(req.session.captcha.tipo);

    return res.status(401).json({
      ok: false,
      intentosRestantes: req.session.intentosCaptcha,
      desafio: captcha.parteMostrable(req.session.captcha),
      errores: ["La respuesta no es correcta. Inténtalo con el desafío nuevo."]
    });
  }

  /* Acertó: ahora sí. No hace falta renovar la sesión otra vez, porque este
     identificador nació en POST /login y solo lo conoce este navegador. */
  proteccionLogin.registrarExito(req);

  const usuario = { id: pendiente.id, username: pendiente.username, rol: pendiente.rol };
  descartarPendiente(req);
  req.session.usuario = usuario;

  res.json({
    ok: true,
    autenticado: true,
    username: usuario.username,
    rol: usuario.rol,
    mensaje: "Sesión iniciada."
  });
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
