/* ============================================================================
   fuerzabruta.js — Pruebas de la Fase 9
   Ejecutar con:  npm run test:ip

   Es el entregable "middleware funcional con prueba demostrativa de bloqueo de
   IP tras 5 intentos fallidos consecutivos" de la guía.

   No hace falta Express: se simulan los objetos req y res, que es todo lo que
   un middleware toca.
   ============================================================================ */

const { crearProteccion } = require("../src/fuerzaBruta.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- Dobles de req y res -------------------------------------------------- */
function peticion(ip) {
  return { ip };
}

function respuesta() {
  const r = {
    codigo: null, cuerpo: null, cabeceras: {},
    set(nombre, valor) { r.cabeceras[nombre] = valor; return r; },
    status(c) { r.codigo = c; return r; },
    json(cuerpo) { r.cuerpo = cuerpo; return r; }
  };
  return r;
}

/** Ejecuta el middleware y dice si dejó pasar la petición. */
function pasa(proteccion, req, res = respuesta()) {
  let siguio = false;
  proteccion.middleware(req, res, () => { siguio = true; });
  return { siguio, res };
}

/** Simula un intento de login fallido completo: middleware + fallo de credenciales. */
function intentoFallido(proteccion, ip) {
  const req = peticion(ip);
  const resultado = pasa(proteccion, req);
  if (!resultado.siguio) return { bloqueadoAntes: true, res: resultado.res };
  const fallo = proteccion.registrarFallo(req);
  return { bloqueadoAntes: false, fallo, res: resultado.res };
}

/* ==========================================================================
   1. Demostración del entregable: 5 fallos consecutivos bloquean la IP
   ========================================================================== */
console.log("\n=== Bloqueo tras 5 intentos fallidos (valores de la guía) ===");
const guia = crearProteccion(); // 5 intentos, ventana y bloqueo de 15 minutos
const IP = "203.0.113.45";

const intentos = [];
for (let i = 1; i <= 5; i++) intentos.push(intentoFallido(guia, IP));

probar("Los 5 primeros intentos llegan al controlador de login",
  intentos.every((i) => i.bloqueadoAntes === false));
probar("El contador de intentos restantes va bajando de 4 a 1",
  intentos[0].fallo.intentosRestantes === 4 && intentos[3].fallo.intentosRestantes === 1);
probar("El quinto fallo activa el bloqueo de la IP", intentos[4].fallo.bloqueado === true);

const sexto = pasa(guia, peticion(IP));
probar("La sexta petición ya NO llega al controlador", sexto.siguio === false);
probar("Responde con código 429 Too Many Requests", sexto.res.codigo === 429);
probar("El cuerpo indica que el bloqueo es por IP", sexto.res.cuerpo.bloqueadoPorIP === true);
probar("Informa cuántos segundos faltan", sexto.res.cuerpo.segundosRestantes > 0);
probar("Envía la cabecera estándar Retry-After", sexto.res.cabeceras["Retry-After"] !== undefined);

const septimo = pasa(guia, peticion(IP));
probar("Sigue bloqueada en los intentos siguientes", septimo.siguio === false);

probar("Una IP distinta no se ve afectada", pasa(guia, peticion("198.51.100.7")).siguio === true);

/* ==========================================================================
   2. Comportamiento con usuarios legítimos
   ========================================================================== */
console.log("\n=== Usuarios legítimos ===");
const normal = crearProteccion();
const IP_BUENA = "192.0.2.10";

intentoFallido(normal, IP_BUENA);
intentoFallido(normal, IP_BUENA);
const reqExito = peticion(IP_BUENA);
pasa(normal, reqExito);
normal.registrarExito(reqExito);

probar("Un inicio de sesión correcto borra los fallos de esa IP", normal.tamano === 0);
probar("Después del acierto, vuelven a hacer falta 5 fallos para bloquear",
  [1, 2, 3, 4].every((_, i) => intentoFallido(normal, IP_BUENA).fallo.bloqueado === false));

/* ==========================================================================
   3. Ventanas de tiempo (con milisegundos en vez de minutos)
   ========================================================================== */
console.log("\n=== Ventanas de tiempo ===");

const rapida = crearProteccion({ maxIntentos: 3, ventanaMs: 40, bloqueoMs: 60, limpiezaMs: 10 });
const IP_R = "192.0.2.55";

intentoFallido(rapida, IP_R);
intentoFallido(rapida, IP_R);

async function esperar(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function principal() {
  await esperar(60); // se pasa la ventana de observación sin llegar al límite
  const trasVentana = intentoFallido(rapida, IP_R);
  probar("Si los fallos se separan más que la ventana, el contador se reinicia",
    trasVentana.fallo.intentosRestantes === 2);

  // Ahora sí, tres seguidos
  intentoFallido(rapida, IP_R);
  const bloqueo = intentoFallido(rapida, IP_R);
  probar("Tres fallos dentro de la ventana bloquean", bloqueo.fallo.bloqueado === true);
  probar("Durante el bloqueo no pasa nada", pasa(rapida, peticion(IP_R)).siguio === false);

  await esperar(80); // expira el bloqueo
  probar("Cuando el bloqueo vence, la IP vuelve a pasar",
    pasa(rapida, peticion(IP_R)).siguio === true);

  /* ========================================================================
     4. Detalles de implementación que al ejemplo de la guía le faltan
     ======================================================================== */
  console.log("\n=== Detalles de implementación ===");

  const limpieza = crearProteccion({ maxIntentos: 3, ventanaMs: 20, bloqueoMs: 20, limpiezaMs: 0 });
  for (let i = 0; i < 50; i++) intentoFallido(limpieza, `198.51.100.${i}`);
  const antes = limpieza.tamano;
  await esperar(40);
  limpieza.limpiar();
  probar("Las IP vencidas se borran y el Map no crece sin control",
    antes === 50 && limpieza.tamano === 0);

  const ipv6 = crearProteccion({ maxIntentos: 2 });
  intentoFallido(ipv6, "::ffff:203.0.113.9");
  const mismaIP = intentoFallido(ipv6, "203.0.113.9");
  probar("::ffff:203.0.113.9 y 203.0.113.9 comparten contador",
    mismaIP.fallo.bloqueado === true && ipv6.tamano === 1);

  const sinIP = crearProteccion({ maxIntentos: 2 });
  intentoFallido(sinIP, undefined);
  probar("Una petición sin IP identificable no rompe el middleware", sinIP.tamano === 1);

  const paraPanel = crearProteccion({ maxIntentos: 2 });
  intentoFallido(paraPanel, "203.0.113.77");
  intentoFallido(paraPanel, "203.0.113.77");
  const foto = paraPanel.estado();
  probar("estado() reporta las IP bloqueadas para el panel del administrador",
    foto.length === 1 && foto[0].ip === "203.0.113.77" && foto[0].bloqueada === true);

  paraPanel.reiniciar();
  probar("reiniciar() limpia todos los bloqueos", paraPanel.tamano === 0);

  console.log(`\n----------------------------------------`);
  console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
  console.log(`----------------------------------------\n`);
  process.exit(falladas === 0 ? 0 : 1);
}

principal();
