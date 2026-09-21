/* ============================================================================
   https.js — Pruebas de la Fase S1 (HTTPS y redirección)
   Ejecutar con:  npm run test:https

   Genera un certificado autofirmado de verdad con openssl, levanta los dos
   servidores (HTTPS y redirección) en puertos libres, y los prueba con
   peticiones reales. No necesita Express: la aplicación de prueba es una
   función mínima de Node.
   ============================================================================ */

const { execFileSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");
const { configuracionTLS, manejadorRedireccion, arrancar } = require("../src/https.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- Preparación: carpeta temporal, certificado y token ------------------ */
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "tls-prueba-"));
const CERT = path.join(TMP, "cert.pem");
const KEY = path.join(TMP, "key.pem");
const ACME = path.join(TMP, "acme");
fs.mkdirSync(ACME);

try {
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", KEY, "-out", CERT, "-days", "1",
    "-subj", "/CN=localhost"
  ], { stdio: "ignore" });
} catch (e) {
  console.error("\n  No se encontró openssl. Instálalo (dnf install openssl) y vuelve a intentar.\n");
  process.exit(1);
}

const TOKEN = "prueba_Token-123";
fs.writeFileSync(path.join(ACME, TOKEN), "contenido-del-desafio");

const PUERTO_HTTPS = 4100 + Math.floor(Math.random() * 400);
const PUERTO_HTTP = PUERTO_HTTPS + 500;

/* --- Utilidades de petición ---------------------------------------------- */
function pedirHttp(ruta, host = "localhost") {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port: PUERTO_HTTP, path: ruta, headers: { Host: host } }, (res) => {
      let cuerpo = "";
      res.on("data", (d) => (cuerpo += d));
      res.on("end", () => resolve({ estado: res.statusCode, destino: res.headers.location, cuerpo }));
    }).on("error", reject);
  });
}

function pedirHttps(ruta) {
  return new Promise((resolve, reject) => {
    https.get({
      host: "127.0.0.1", port: PUERTO_HTTPS, path: ruta,
      rejectUnauthorized: false // el certificado es autofirmado: es justo la "problemática"
    }, (res) => {
      // El protocolo se lee al llegar la respuesta: al terminar, el socket ya se liberó.
      const protocolo = res.socket.getProtocol();
      let cuerpo = "";
      res.on("data", (d) => (cuerpo += d));
      res.on("end", () => resolve({ estado: res.statusCode, cuerpo, protocolo }));
    }).on("error", reject);
  });
}

function pedirHttpsEstricto(ruta) {
  return new Promise((resolve) => {
    https.get({ host: "127.0.0.1", port: PUERTO_HTTPS, path: ruta }, () => resolve({ aceptado: true }))
      .on("error", (e) => resolve({ aceptado: false, codigo: e.code }));
  });
}

async function principal() {
  /* --- 1. Lectura de la configuración ------------------------------------ */
  console.log("\n=== Configuración ===");
  probar("Sin variables TLS, el servidor queda en modo HTTP", configuracionTLS({}) === null);

  const tls = configuracionTLS({
    TLS_CERT: CERT, TLS_KEY: KEY,
    HTTPS_PORT: String(PUERTO_HTTPS), HTTP_PORT: String(PUERTO_HTTP), ACME_DIR: ACME
  });
  probar("Con TLS_CERT y TLS_KEY se leen el certificado y la llave", tls && tls.cert.length > 0 && tls.key.length > 0);
  probar("Los puertos por defecto son 443 y 80",
    (() => { const t = configuracionTLS({ TLS_CERT: CERT, TLS_KEY: KEY }); return t.puertoHttps === 443 && t.puertoHttp === 80; })());

  const lanza = (env) => { try { configuracionTLS(env); return false; } catch (e) { return true; } };
  probar("Solo el certificado sin la llave es un error, no un HTTP silencioso", lanza({ TLS_CERT: CERT }));
  probar("Solo la llave sin el certificado también es un error", lanza({ TLS_KEY: KEY }));
  probar("Una ruta inexistente es un error con mensaje claro",
    (() => { try { configuracionTLS({ TLS_CERT: "/no/existe.pem", TLS_KEY: KEY }); return false; }
             catch (e) { return e.message.includes("/no/existe.pem"); } })());

  /* --- 2. Servidores reales ---------------------------------------------- */
  const aplicacion = (req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.end("aplicacion:" + req.url);
  };
  const servidores = arrancar(aplicacion, tls);
  await new Promise((r) => setTimeout(r, 300));

  try {
    console.log("\n=== Puerto HTTPS ===");
    const segura = await pedirHttps("/login.html");
    probar("La aplicación responde por HTTPS", segura.estado === 200 && segura.cuerpo === "aplicacion:/login.html");
    probar(`La conexión usa TLS 1.2 o superior (${segura.protocolo})`, /^TLSv1\.[23]$/.test(segura.protocolo));

    const estricto = await pedirHttpsEstricto("/");
    probar(`Un cliente que valida certificados RECHAZA el autofirmado (${estricto.codigo})`,
      estricto.aceptado === false);

    console.log("\n=== Puerto HTTP: redirección ===");
    const raiz = await pedirHttp("/", "midominio.xyz");
    probar("La raíz por HTTP responde 301", raiz.estado === 301);
    probar("Redirige a la misma dirección por HTTPS",
      raiz.destino === `https://midominio.xyz:${PUERTO_HTTPS}/`);

    const ruta = await pedirHttp("/panel.html?x=1", "midominio.xyz");
    probar("Conserva la ruta y la query al redirigir",
      ruta.destino === `https://midominio.xyz:${PUERTO_HTTPS}/panel.html?x=1`);

    const conPuerto = await pedirHttp("/", "midominio.xyz:80");
    probar("Quita el puerto 80 de la cabecera Host antes de redirigir",
      conPuerto.destino === `https://midominio.xyz:${PUERTO_HTTPS}/`);

    const login = await pedirHttp("/login");
    probar("El puerto HTTP NUNCA sirve la aplicación, ni siquiera el login",
      login.estado === 301 && !login.cuerpo.includes("aplicacion"));

    console.log("\n=== Puerto HTTP: desafío de Let's Encrypt ===");
    const desafio = await pedirHttp(`/.well-known/acme-challenge/${TOKEN}`);
    probar("El token del desafío se sirve por HTTP, sin redirigir",
      desafio.estado === 200 && desafio.cuerpo === "contenido-del-desafio");

    const inexistente = await pedirHttp("/.well-known/acme-challenge/noexiste");
    probar("Un token inexistente responde 404", inexistente.estado === 404);

    const traversal = await pedirHttp("/.well-known/acme-challenge/..%2F..%2Fserver.js");
    probar("Un intento de path traversal se rechaza con 400", traversal.estado === 400);

    const traversal2 = await pedirHttp("/.well-known/acme-challenge/../../etc/passwd");
    probar("Tampoco con ../ sin codificar", traversal2.estado !== 200);

    console.log("\n=== Dominio fijo ===");
    const fijo = manejadorRedireccion({ puertoHttps: 443, dominio: "www.midominio.xyz", carpetaAcme: ACME });
    let destino = null;
    fijo({ url: "/x", headers: { host: "atacante.com" } },
         { writeHead: (c, h) => { destino = h && h.Location; }, end: () => {} });
    probar("Con DOMINIO definido se ignora la cabecera Host del cliente",
      destino === "https://www.midominio.xyz/x");
  } finally {
    servidores.forEach((s) => s.close());
    fs.rmSync(TMP, { recursive: true, force: true });
  }

  console.log(`\n----------------------------------------`);
  console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
  console.log(`----------------------------------------\n`);
  process.exit(falladas === 0 ? 0 : 1);
}

principal().catch((e) => {
  console.error("\n  Error en la prueba: " + e.message + "\n");
  process.exit(1);
});
