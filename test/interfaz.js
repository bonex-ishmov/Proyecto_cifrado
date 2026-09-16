/* ============================================================================
   interfaz.js — Prueba de humo de la interfaz
   Ejecutar con:  npm run test:interfaz

   No hay navegador en la consola, así que se simula un DOM mínimo (los cuatro
   métodos que usa app.js) y se ejecutan cripto.js y app.js dentro de un
   contexto aislado. Sirve para detectar errores de renderizado sin abrir
   Chrome: campos que quedan en "undefined", excepciones al pintar tablas, etc.
   ============================================================================ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const PRIVADO = path.join(__dirname, "..", "privado");

/* --- DOM simulado -------------------------------------------------------- */
function crearNodo(id) {
  return {
    id, value: "", textContent: "", innerHTML: "", dataset: {},
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {},
    scrollIntoView() {},
    querySelectorAll: () => [],
    querySelector: () => ({ addEventListener() {} })
  };
}

const nodos = {};
const contexto = {
  console,
  navigator: { clipboard: { writeText() {} } },
  window: {},
  // app.js consulta /sesion al cargar; en la consola no hay servidor, así que
  // se simula una respuesta de "sin sesión iniciada".
  fetch: async () => ({ ok: false, json: async () => ({ ok: false, usuario: null }) }),
  setTimeout, clearTimeout, setInterval, clearInterval,
  document: {
    getElementById: (id) => (nodos[id] = nodos[id] || crearNodo(id)),
    querySelectorAll: () => []
  }
};
vm.createContext(contexto);
vm.runInContext(fs.readFileSync(path.join(PRIVADO, "cripto.js"), "utf8"), contexto);
vm.runInContext(fs.readFileSync(path.join(PRIVADO, "app.js"), "utf8"), contexto);

const $ = (id) => contexto.document.getElementById(id);
const ejecutar = (codigo) => vm.runInContext(codigo, contexto);

/* --- Aserciones ---------------------------------------------------------- */
let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- 1. Cada reto de la guía se analiza desde la interfaz ---------------- */
console.log("\n=== Botones de los retos de la guía ===");
const RETOS_GUIA = ejecutar("RETOS_GUIA");
const CLAVES_ESPERADAS = ["k = 5", "a = 5, b = 7", "clave = NUBE"];

RETOS_GUIA.forEach((reto, i) => {
  $("criptograma").value = reto.criptograma;
  $("metodo").value = "";
  $("longitudClave").value = "";
  ejecutar("analizarCriptograma()");

  const html = $("resultado").innerHTML;
  const clave = (html.match(/class="clave">([^<]+)/) || [])[1];

  probar(`${reto.titulo}: la interfaz muestra ${CLAVES_ESPERADAS[i]}`, clave === CLAVES_ESPERADAS[i]);
  probar(`${reto.titulo}: el HTML no trae undefined ni NaN`,
    !html.includes("undefined") && !html.includes("NaN"));
  probar(`${reto.titulo}: se pintan las tablas de evidencia`, html.split("<table").length >= 3);
});

/* --- 2. Modo cifrar ------------------------------------------------------ */
console.log("\n=== Modo cifrar ===");
$("textoClaro").value = "Habla sobre la historia";
$("metodoCifrado").value = "cesar";
$("claveK").value = "5";
ejecutar("cifrarTexto()");
probar("César cifra desde la interfaz", $("textoCifrado").textContent === "MFGPFXTGWJPFMNXYTWNF");

$("metodoCifrado").value = "afin";
$("claveA").value = "3";
$("claveB").value = "4";
ejecutar("cifrarTexto()");
probar("Una clave 'a' inválida muestra el error en pantalla",
  $("errorCifrado").textContent.includes("coprima"));

/* --- 3. Errores del analizador ------------------------------------------ */
console.log("\n=== Manejo de errores ===");
$("criptograma").value = "1234 !!!";
ejecutar("analizarCriptograma()");
probar("Un texto sin letras muestra un mensaje claro",
  $("errorAnalisis").textContent.includes("ninguna letra"));

/* --- 4. Ataque forzado --------------------------------------------------- */
console.log("\n=== Ataque forzado desde el selector ===");
$("criptograma").value = RETOS_GUIA[0].criptograma;
$("metodo").value = "vigenere";
ejecutar("analizarCriptograma()");
probar("Forzar Vigenère sobre un César muestra el aviso de ataque forzado",
  $("resultado").innerHTML.includes("forzado"));

console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
