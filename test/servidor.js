/* ============================================================================
   servidor.js — Prueba de humo de extremo a extremo
   Ejecutar con:  npm run test:servidor

   Levanta el servidor DE VERDAD, con Express, sesiones y base de datos, en un
   puerto libre y contra una base temporal. Luego recorre el flujo completo con
   peticiones HTTP reales.

   Por qué existe: las demás pruebas verifican cada pieza por separado y todas
   pasaban cuando el login dejó de funcionar por tener los middlewares en mal
   orden en server.js. Lo que falla en un despliegue casi nunca es una función
   suelta, es el cableado. Esto lo comprueba.

   Correr SIEMPRE antes de desplegar.
   ============================================================================ */

const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const RAIZ = path.join(__dirname, "..");
const PUERTO = 3100 + Math.floor(Math.random() * 800);
const BASE = `http://127.0.0.1:${PUERTO}`;
const RUTA_BD = path.join(os.tmpdir(), `auth-humo-${Date.now()}.db`);

/* Un CAPTCHA que funcione no lo puede resolver un programa: ese es su trabajo.
   El servidor se arranca con CAPTCHA_PRUEBA, que fija la respuesta a este
   valor conocido para poder recorrer el flujo entero. Esa variable y un
   certificado configurado son incompatibles (ver server.js), así que este modo
   no existe en producción. */
const RESPUESTA_FIJA = "HUMANO";

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- Tarro de galletas: guarda la cookie de sesión entre peticiones -------- */
let cookie = "";

async function pedir(ruta, opciones = {}) {
  const cabeceras = { ...(opciones.headers || {}) };
  if (cookie) cabeceras.Cookie = cookie;
  if (opciones.json) {
    cabeceras["Content-Type"] = "application/json";
    opciones.body = JSON.stringify(opciones.json);
    opciones.method = opciones.method || "POST";
  }

  const respuesta = await fetch(BASE + ruta, {
    ...opciones, headers: cabeceras, redirect: "manual"
  });

  const nuevas = typeof respuesta.headers.getSetCookie === "function"
    ? respuesta.headers.getSetCookie()
    : [respuesta.headers.get("set-cookie")].filter(Boolean);
  if (nuevas.length) cookie = nuevas.map((c) => c.split(";")[0]).join("; ");

  let cuerpo = null;
  const texto = await respuesta.text();
  try { cuerpo = JSON.parse(texto); } catch (e) { cuerpo = texto; }

  return { estado: respuesta.status, destino: respuesta.headers.get("location"), cuerpo };
}

/* --- Arranque del servidor ------------------------------------------------ */
function arrancar() {
  return new Promise((resolve, reject) => {
    const hijo = spawn(process.execPath, ["server.js"], {
      cwd: RAIZ,
      env: { ...process.env, PORT: String(PUERTO), DB_PATH: RUTA_BD,
              SESSION_SECRET: "prueba-de-humo", CAPTCHA_PRUEBA: RESPUESTA_FIJA }
    });

    const limite = setTimeout(() => reject(new Error("El servidor no arrancó en 10 segundos.")), 10000);

    hijo.stdout.on("data", (dato) => {
      if (String(dato).includes("escuchando")) { clearTimeout(limite); resolve(hijo); }
    });
    hijo.stderr.on("data", (dato) => {
      const texto = String(dato);
      if (texto.includes("ExperimentalWarning")) return; // aviso de node:sqlite
      console.error("  [servidor] " + texto.trim());
    });
    hijo.on("exit", (codigo) => {
      clearTimeout(limite);
      reject(new Error(`El servidor terminó con código ${codigo} antes de escuchar.`));
    });
  });
}

/* ========================================================================== */
async function principal() {
  const servidor = await arrancar();

  try {
    /* --- Sin sesión ------------------------------------------------------ */
    console.log("\n=== Sin sesión iniciada ===");
    const raiz = await pedir("/");
    probar("La raíz redirige al login", raiz.estado === 302 && raiz.destino === "/login.html");
    probar("Pedir cripto.js a mano también redirige",
      (await pedir("/cripto.js")).estado === 302);
    probar("El panel redirige igual", (await pedir("/panel.html")).estado === 302);
    probar("La página de login sí se sirve", (await pedir("/login.html")).estado === 200);
    probar("La hoja de estilos es pública", (await pedir("/estilos.css")).estado === 200);
    probar("/sesion responde 401 sin cookie", (await pedir("/sesion")).estado === 401);
    probar("/usuarios responde 401 sin cookie", (await pedir("/usuarios")).estado === 401);

    /* --- Registro -------------------------------------------------------- */
    console.log("\n=== Registro ===");
    const alta = await pedir("/registro", { json: { username: "manuela", password: "ClaveSegura123" } });
    probar("Crear una cuenta responde 201", alta.estado === 201 && alta.cuerpo.ok === true);
    probar("La cuenta nueva tiene rol Usuario", alta.cuerpo.rol === "Usuario");

    const intruso = await pedir("/registro", {
      json: { username: "intruso", password: "ClaveSegura123", rol: "Administrador", rol_id: 1 }
    });
    probar("Pedir rol Administrador en el registro no sirve de nada",
      intruso.estado === 201 && intruso.cuerpo.rol === "Usuario");

    probar("Repetir el nombre de usuario responde 409",
      (await pedir("/registro", { json: { username: "manuela", password: "OtraClave123" } })).estado === 409);
    probar("Datos inválidos responden 400",
      (await pedir("/registro", { json: { username: "ab", password: "1" } })).estado === 400);

    /* --- Login ----------------------------------------------------------- */
    console.log("\n=== Inicio de sesión ===");
    probar("Contraseña incorrecta responde 401",
      (await pedir("/login", { json: { username: "manuela", password: "malamala" } })).estado === 401);

    const entrada = await pedir("/login", { json: { username: "manuela", password: "ClaveSegura123" } });
    probar("Credenciales correctas responden 200", entrada.estado === 200 && entrada.cuerpo.ok === true);
    probar("Pero la sesión TODAVÍA no se abre: el servidor pide el CAPTCHA",
      entrada.cuerpo.requiereCaptcha === true && entrada.cuerpo.autenticado === false);
    probar("El servidor entregó una cookie de sesión", cookie.includes("sid"));

    /* --- Comprobación humana --------------------------------------------- */
    console.log("\n=== Comprobación humana (CAPTCHA) ===");

    const aMedias = await pedir("/");
    probar("Con la contraseña acertada pero sin CAPTCHA, la raíz sigue cerrada",
      aMedias.estado === 302 && aMedias.destino === "/captcha.html");
    probar("cripto.js tampoco se descarga todavía", (await pedir("/cripto.js")).estado === 302);
    probar("/sesion sigue respondiendo que no hay nadie", (await pedir("/sesion")).estado === 401);
    probar("/perfil sigue cerrado", (await pedir("/perfil")).estado === 401);
    probar("La página del CAPTCHA sí se sirve", (await pedir("/captcha.html")).estado === 200);

    const desafio = await pedir("/captcha");
    probar("El servidor entrega un desafío", desafio.estado === 200 && desafio.cuerpo.ok === true);
    probar("El desafío trae enunciado y dibujo",
      typeof desafio.cuerpo.desafio.enunciado === "string" &&
      Boolean(desafio.cuerpo.desafio.svg || desafio.cuerpo.desafio.celdas));
    probar("El desafío NO trae la respuesta",
      !("respuesta" in desafio.cuerpo.desafio));
    probar("Se anuncian tres intentos", desafio.cuerpo.intentosRestantes === 3);

    const fallo = await pedir("/captcha", { json: { respuesta: "respuesta-equivocada" } });
    probar("Una respuesta incorrecta responde 401", fallo.estado === 401);
    probar("Y descuenta un intento", fallo.cuerpo.intentosRestantes === 2);
    probar("Y llega un desafío nuevo, no el mismo", Boolean(fallo.cuerpo.desafio));
    probar("Tras fallar sigue sin haber sesión", (await pedir("/sesion")).estado === 401);

    const acierto = await pedir("/captcha", { json: { respuesta: RESPUESTA_FIJA } });
    probar("La respuesta correcta abre la sesión", acierto.estado === 200 && acierto.cuerpo.ok === true);
    probar("Y el servidor confirma usuario y rol",
      acierto.cuerpo.username === "manuela" && acierto.cuerpo.rol === "Usuario");

    /* --- Con sesión de usuario normal ------------------------------------ */
    console.log("\n=== Con sesión de usuario ===");
    const herramienta = await pedir("/");
    probar("Ahora la raíz entrega la herramienta",
      herramienta.estado === 200 && String(herramienta.cuerpo).includes("Criptoan"));
    probar("cripto.js ya se descarga", (await pedir("/cripto.js")).estado === 200);
    probar("/sesion identifica al usuario",
      (await pedir("/sesion")).cuerpo.usuario.username === "manuela");
    probar("/perfil devuelve los datos propios",
      (await pedir("/perfil")).cuerpo.perfil.rol === "Usuario");

    const prohibido = await pedir("/usuarios");
    probar("Un usuario normal recibe 403 en la ruta de administrador", prohibido.estado === 403);
    probar("Y también al intentar desbloquear cuentas",
      (await pedir("/usuarios/1/desbloquear", { method: "POST" })).estado === 403);

    /* --- Cierre de sesión ------------------------------------------------ */
    console.log("\n=== Cierre de sesión ===");
    probar("El logout responde ok", (await pedir("/logout", { method: "POST" })).cuerpo.ok === true);
    probar("Tras cerrar sesión, la raíz vuelve a redirigir", (await pedir("/")).estado === 302);

    /* --- El CAPTCHA no se puede saltar ------------------------------------ */
    console.log("\n=== El paso intermedio no se puede saltar ===");

    probar("Sin inicio de sesión en curso, pedir un desafío responde 401",
      (await pedir("/captcha")).estado === 401);
    probar("Y contestarlo a pelo tampoco sirve",
      (await pedir("/captcha", { json: { respuesta: RESPUESTA_FIJA } })).estado === 401);

    await pedir("/login", { json: { username: "manuela", password: "ClaveSegura123" } });
    let ultimoFallo = null;
    for (let i = 0; i < 3; i++) {
      ultimoFallo = await pedir("/captcha", { json: { respuesta: "sigo-sin-acertar" } });
    }
    probar("Al tercer fallo se tira el inicio de sesión a medias",
      ultimoFallo.estado === 401 && ultimoFallo.cuerpo.reiniciar === true);
    probar("Y ya no hay desafío que pedir", (await pedir("/captcha")).estado === 401);
    probar("Haber acertado la contraseña antes no deja sesión abierta",
      (await pedir("/sesion")).estado === 401);
    probar("La raíz vuelve a mandar al login, no al CAPTCHA",
      (await pedir("/")).destino === "/login.html");

    /* --- Fuerza bruta ---------------------------------------------------- */
    console.log("\n=== Bloqueo tras intentos fallidos ===");
    const codigos = [];
    for (let i = 0; i < 6; i++) {
      codigos.push((await pedir("/login", { json: { username: "manuela", password: "malamala" } })).estado);
    }
    console.log(`        códigos devueltos: ${codigos.join(" ")}`);
    probar("Los primeros intentos responden 401", codigos.slice(0, 4).every((c) => c === 401));
    probar("A partir del quinto se bloquea (423 cuenta o 429 IP)",
      [423, 429].includes(codigos[4]) && [423, 429].includes(codigos[5]));

    const bloqueada = await pedir("/login", { json: { username: "manuela", password: "ClaveSegura123" } });
    probar("Ni con la contraseña correcta se entra estando bloqueada",
      [423, 429].includes(bloqueada.estado));

  } finally {
    servidor.kill();
    if (fs.existsSync(RUTA_BD)) fs.unlinkSync(RUTA_BD);
  }

  console.log(`\n----------------------------------------`);
  console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
  console.log(`----------------------------------------\n`);
  process.exit(falladas === 0 ? 0 : 1);
}

principal().catch((e) => {
  console.error("\n  No se pudo completar la prueba: " + e.message + "\n");
  process.exit(1);
});
