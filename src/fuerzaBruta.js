/* ============================================================================
   fuerzaBruta.js — Middleware propio de protección contra fuerza bruta
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Segunda defensa del proyecto, complementaria al bloqueo por cuenta de
   src/login.js: aquí se cuenta por DIRECCIÓN IP, sin importar a qué cuenta
   apunten los intentos. Detiene a quien prueba miles de usuarios distintos,
   caso en el que ningún contador por cuenta llegaría nunca a cinco.

   Está construido sobre el ejemplo de la Sección 3.3 de la guía, con cuatro
   diferencias necesarias:

     1. El ejemplo LEE `registro.conteo` y `registro.bloqueadoHasta` pero nunca
        los escribe, así que tal como está publicado no bloquea nada. Aquí el
        incremento ocurre en registrarFallo(), que llama la ruta de login
        cuando las credenciales fallan.
     2. Se cuentan FALLOS, no peticiones: un usuario legítimo que se equivoca
        una vez y entra bien a la segunda no debe gastar cupo.
     3. Se limpian las entradas vencidas. El Map del ejemplo crece con cada IP
        nueva y nunca suelta memoria, que es una forma lenta de tumbar el
        servidor.
     4. Se normaliza la IP, porque Node entrega 127.0.0.1 como ::ffff:127.0.0.1
        y quedarían dos contadores para la misma máquina.

   LÍMITE CONOCIDO: el estado vive en la memoria de este proceso. Al reiniciar
   el servidor los bloqueos se pierden, y con varias instancias cada una
   contaría por su lado. La solución sería un almacén compartido tipo Redis,
   como menciona la guía; para un servidor único es innecesario.
   ============================================================================ */

/**
 * Crea una instancia de la protección. Es una fábrica y no un objeto único
 * para poder probarla con ventanas de milisegundos en vez de minutos.
 */
function crearProteccion(opciones = {}) {
  const MAX_INTENTOS = opciones.maxIntentos ?? 5;
  const VENTANA_MS = opciones.ventanaMs ?? 15 * 60 * 1000;
  const BLOQUEO_MS = opciones.bloqueoMs ?? 15 * 60 * 1000;
  const LIMPIEZA_MS = opciones.limpiezaMs ?? 5 * 60 * 1000;

  /** ip -> { conteo, primerIntento, bloqueadoHasta } */
  const intentosIP = new Map();
  let ultimaLimpieza = Date.now();

  /** ::ffff:127.0.0.1 y 127.0.0.1 son la misma máquina: un solo contador. */
  function ipDe(req) {
    const cruda = (req && (req.ip || (req.connection && req.connection.remoteAddress))) || "desconocida";
    return String(cruda).replace(/^::ffff:/, "");
  }

  /** Borra las IP cuya ventana y bloqueo ya vencieron. Evita que el Map crezca sin fin. */
  function limpiar(ahora = Date.now()) {
    for (const [ip, registro] of intentosIP) {
      const vencioBloqueo = registro.bloqueadoHasta <= ahora;
      const vencioVentana = ahora - registro.primerIntento > VENTANA_MS;
      if (vencioBloqueo && vencioVentana) intentosIP.delete(ip);
    }
    ultimaLimpieza = ahora;
  }

  function registroDe(ip, ahora) {
    if (!intentosIP.has(ip)) {
      intentosIP.set(ip, { conteo: 0, primerIntento: ahora, bloqueadoHasta: 0 });
    }
    const registro = intentosIP.get(ip);

    // Si la ventana de observación expiró, se empieza a contar de cero.
    if (registro.bloqueadoHasta <= ahora && ahora - registro.primerIntento > VENTANA_MS) {
      registro.conteo = 0;
      registro.primerIntento = ahora;
    }
    return registro;
  }

  /* --------------------------------------------------------------------------
     Middleware: se ejecuta ANTES del controlador de /login. Si la IP está
     bloqueada, corta la petición ahí mismo y el controlador nunca se entera.
  -------------------------------------------------------------------------- */
  function middleware(req, res, next) {
    const ahora = Date.now();
    if (ahora - ultimaLimpieza > LIMPIEZA_MS) limpiar(ahora);

    const ip = ipDe(req);
    const registro = registroDe(ip, ahora);

    if (registro.bloqueadoHasta > ahora) {
      const segundosRestantes = Math.ceil((registro.bloqueadoHasta - ahora) / 1000);
      // Cabecera estándar para que un cliente automático sepa cuándo reintentar.
      if (typeof res.set === "function") res.set("Retry-After", String(segundosRestantes));
      return res.status(429).json({
        ok: false,
        bloqueadoPorIP: true,
        segundosRestantes,
        errores: [`Demasiados intentos fallidos desde esta dirección. ` +
                  `Inténtalo de nuevo en ${segundosRestantes} segundos.`]
      });
    }

    // El controlador usará esto para contar el fallo si las credenciales no sirven.
    req.registroIP = registro;
    req.ipNormalizada = ip;
    next();
  }

  /** Suma un fallo a la IP de la petición y bloquea si se pasó del límite. */
  function registrarFallo(req) {
    const ahora = Date.now();
    const registro = registroDe(ipDe(req), ahora);

    registro.conteo += 1;
    if (registro.conteo >= MAX_INTENTOS) {
      registro.bloqueadoHasta = ahora + BLOQUEO_MS;
      registro.conteo = 0;              // el ciclo vuelve a empezar tras el bloqueo
      registro.primerIntento = ahora;
      return { bloqueado: true, intentosRestantes: 0, segundosRestantes: Math.ceil(BLOQUEO_MS / 1000) };
    }
    return { bloqueado: false, intentosRestantes: MAX_INTENTOS - registro.conteo, segundosRestantes: 0 };
  }

  /** Un inicio de sesión correcto borra el historial de esa IP. */
  function registrarExito(req) {
    intentosIP.delete(ipDe(req));
  }

  /** Foto del estado actual. La usa el panel del administrador (Fase 10). */
  function estado() {
    const ahora = Date.now();
    return Array.from(intentosIP.entries()).map(([ip, r]) => ({
      ip,
      intentosFallidos: r.conteo,
      bloqueada: r.bloqueadoHasta > ahora,
      segundosRestantes: r.bloqueadoHasta > ahora ? Math.ceil((r.bloqueadoHasta - ahora) / 1000) : 0
    }));
  }

  /** Borra todo. Para las pruebas y para el botón de desbloqueo del panel. */
  function reiniciar() {
    intentosIP.clear();
  }

  return {
    middleware, registrarFallo, registrarExito, estado, reiniciar, limpiar,
    MAX_INTENTOS, VENTANA_MS, BLOQUEO_MS,
    get tamano() { return intentosIP.size; }
  };
}

/* Instancia que usa el servidor, con los valores de la guía:
   5 intentos fallidos, ventana de 15 minutos, bloqueo de 15 minutos. */
const proteccionLogin = crearProteccion();

module.exports = { crearProteccion, proteccionLogin };
