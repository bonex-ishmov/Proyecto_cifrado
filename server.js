/* ============================================================================
   server.js  —  Servidor único del taller
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Desarrollo:  node server.js        -> http://localhost:80
   ============================================================================ */

const express = require("express");
const path = require("path");

const app = express();
const PUERTO = process.env.PORT || 3000;

// Único middleware: servir la carpeta public (index.html se entrega en "/")
app.use(express.static(path.join(__dirname, "public")));

app.listen(PUERTO, () => {
  console.log(`Servidor escuchando en http://localhost:${PUERTO}`);
});
