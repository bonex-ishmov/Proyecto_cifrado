/* ============================================================================
   https.js — Arranque del servidor con o sin certificado
   Universidad El Bosque — Seguridad de la Información — 2026-II

   El certificado NO está escrito en el código. Se activa desde fuera con dos
   variables de entorno que apuntan a los archivos:

       TLS_CERT=/ruta/al/certificado.pem
       TLS_KEY=/ruta/a/la/llave-privada.pem

   · Sin esas variables: un solo servidor HTTP, como antes. Es el modo de
     desarrollo y el que usan las pruebas.
   · Con ellas: dos servidores.
       - HTTPS (puerto 443): la aplicación completa.
       - HTTP  (puerto 80):  no sirve la aplicación. Solo redirige a HTTPS y
         responde el desafío de Let's Encrypt.

   Cambiar del certificado autofirmado al de Let's Encrypt es cambiar esas dos
   rutas y reiniciar. Esa es la "activación manual" que pide la guía.
   ============================================================================ */

const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");

const RAIZ = path.join(__dirname, "..");
const PREFIJO_ACME = "/.well-known/acme-challenge/";

/**
 * Los tokens de Let's Encrypt son base64url: letras, números, guion y guion
 * bajo. Validarlos impide pedir /.well-known/acme-challenge/../../server.js y
 * leer cualquier archivo del servidor (path traversal).
 */
const PATRON_TOKEN = /^[A-Za-z0-9_-]+$/;

/* ---------------------------------------------------------------------------
   Lectura de la configuración
--------------------------------------------------------------------------- */

/**
 * Devuelve null si no hay certificado configurado (modo HTTP).
 * Lanza un error si la configuración está a medias o los archivos no se
 * pueden leer. NUNCA cae en silencio a HTTP: si alguien configuró un
 * certificado y falla, servir sin cifrado sería peor que no arrancar.
 */
function configuracionTLS(env = process.env) {
  const rutaCert = env.TLS_CERT;
  const rutaKey = env.TLS_KEY;

  if (!rutaCert && !rutaKey) return null;
  if (!rutaCert || !rutaKey) {
    throw new Error("Para activar HTTPS hacen falta TLS_CERT y TLS_KEY a la vez.");
  }

  let cert, key;
  try {
    cert = fs.readFileSync(rutaCert);
  } catch (e) {
    throw new Error(`No se pudo leer el certificado ${rutaCert} (${e.code}).`);
  }
  try {
    key = fs.readFileSync(rutaKey);
  } catch (e) {
    throw new Error(`No se pudo leer la llave privada ${rutaKey} (${e.code}). ` +
                    "Revisa que el usuario del servicio tenga permiso de lectura.");
  }

  return {
    cert, key, rutaCert, rutaKey,
    puertoHttps: Number(env.HTTPS_PORT || 443),
    puertoHttp: Number(env.HTTP_PORT || 80),
    dominio: env.DOMINIO || null,
    carpetaAcme: env.ACME_DIR || path.join(RAIZ, "acme-challenge")
  };
}

/* ---------------------------------------------------------------------------
   Servidor del puerto 80: redirección + desafío ACME
   Es Node puro, no Express, a propósito: no debe tener acceso a nada de la
   aplicación. Lo único que sabe hacer es esto.
--------------------------------------------------------------------------- */
function manejadorRedireccion({ puertoHttps = 443, dominio = null, carpetaAcme }) {
  return function (req, res) {
    const url = req.url || "/";

    // 1. Desafío HTTP-01 de Let's Encrypt. Tiene que responderse por HTTP
    //    plano: es como Let's Encrypt comprueba que controlas el dominio
    //    ANTES de que exista un certificado.
    if (url.startsWith(PREFIJO_ACME)) {
      const token = url.slice(PREFIJO_ACME.length).split("?")[0];
      if (!PATRON_TOKEN.test(token)) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        return res.end("Token inválido");
      }
      return fs.readFile(path.join(carpetaAcme, token), (err, contenido) => {
        if (err) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          return res.end("No encontrado");
        }
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(contenido);
      });
    }

    // 2. Cualquier otra cosa: 301 a la misma ruta por HTTPS. Es permanente,
    //    así que el navegador lo recuerda y no vuelve a intentar HTTP.
    const host = dominio || String(req.headers.host || "").replace(/:\d+$/, "");
    if (!host) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      return res.end("Falta la cabecera Host");
    }
    const puerto = puertoHttps === 443 ? "" : `:${puertoHttps}`;
    res.writeHead(301, { Location: `https://${host}${puerto}${url}` });
    res.end();
  };
}

/* ---------------------------------------------------------------------------
   Arranque
--------------------------------------------------------------------------- */
function arrancar(app, tls, env = process.env) {
  if (!tls) {
    const puerto = Number(env.PORT || 3000);
    const servidor = app.listen(puerto, () => {
      console.log(`Servidor escuchando en http://localhost:${puerto} (sin HTTPS)`);
    });
    return [servidor];
  }

  const seguro = https.createServer({ cert: tls.cert, key: tls.key }, app);
  seguro.listen(tls.puertoHttps, () => {
    console.log(`Servidor escuchando en https, puerto ${tls.puertoHttps}`);
    console.log(`  certificado: ${tls.rutaCert}`);
  });

  const redireccion = http.createServer(manejadorRedireccion(tls));
  redireccion.listen(tls.puertoHttp, () => {
    console.log(`Redirección HTTP -> HTTPS escuchando en el puerto ${tls.puertoHttp}`);
  });

  return [seguro, redireccion];
}

module.exports = { configuracionTLS, manejadorRedireccion, arrancar, PATRON_TOKEN };
