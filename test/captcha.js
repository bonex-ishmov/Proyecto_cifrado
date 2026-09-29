/* ============================================================================
   captcha.js — Pruebas del desafío visual
   Ejecutar con:  npm run test:captcha

   Sin librerías, como el resto de suites del proyecto: un probar() con
   contador y process.exit al final.

   Se prueba el MÓDULO, no las rutas. El cableado (que POST /login ya no abre
   sesión, que /captcha la abre, que la raíz sigue protegida) se comprueba de
   extremo a extremo en test/servidor.js, que es donde aparecen los errores de
   verdad.
   ============================================================================ */

const captcha = require("../src/captcha.js");

let pasadas = 0, falladas = 0;
function probar(descripcion, condicion) {
  condicion ? pasadas++ : falladas++;
  console.log(`  ${condicion ? "OK  " : "FALLA"}  ${descripcion}`);
}

/* --- Generación ------------------------------------------------------------ */
console.log("\n=== Generación de las tres variantes ===");

probar("Hay exactamente tres variantes", captcha.TIPOS.length === 3);

for (const tipo of captcha.TIPOS) {
  const desafio = captcha.crearDesafio(tipo);
  probar(`[${tipo}] se genera con el tipo pedido`, desafio.tipo === tipo);
  probar(`[${tipo}] trae una respuesta no vacía`,
    typeof desafio.respuesta === "string" && desafio.respuesta.length > 0);
  probar(`[${tipo}] trae un enunciado para la persona`,
    typeof desafio.enunciado === "string" && desafio.enunciado.length > 10);
  probar(`[${tipo}] trae dibujo (imagen o celdas)`,
    typeof desafio.svg === "string" || Array.isArray(desafio.celdas));
}

probar("Sin argumento sortea una de las tres",
  captcha.TIPOS.includes(captcha.crearDesafio().tipo));

// Si siempre saliera la misma, la "variedad" sería falsa.
const sorteados = new Set();
for (let i = 0; i < 200; i++) sorteados.add(captcha.crearDesafio().tipo);
probar("En 200 sorteos salen las tres variantes", sorteados.size === 3);

/* --- La respuesta nunca sale del servidor ---------------------------------- */
console.log("\n=== La respuesta se queda en el servidor ===");

/* Lista blanca: parteMostrable debe dejar pasar solo estos campos. Se
   comprueba así, y no buscando la respuesta dentro del JSON, porque el dibujo
   es una sopa de coordenadas y un "12" aparece ahí por pura casualidad: esa
   búsqueda daría falsas alarmas sin demostrar nada. Lo que de verdad importa
   es que no se cuele ningún campo nuevo el día que alguien amplíe el módulo. */
const CAMPOS_PERMITIDOS = ["tipo", "modo", "enunciado", "svg", "celdas"];

for (const tipo of captcha.TIPOS) {
  const desafio = captcha.crearDesafio(tipo);
  const publico = captcha.parteMostrable(desafio);

  probar(`[${tipo}] parteMostrable no incluye la respuesta`,
    !("respuesta" in publico));
  probar(`[${tipo}] no se cuela ningún campo fuera de la lista blanca`,
    Object.keys(publico).every((clave) => CAMPOS_PERMITIDOS.includes(clave)));
}

// Este sí es un caso real: cinco caracteres seguidos dentro del dibujo serían
// una fuga de verdad, no una coincidencia.
const soloTexto = captcha.crearDesafio("texto");
probar("[texto] la respuesta no aparece escrita dentro del dibujo",
  !soloTexto.svg.includes(soloTexto.respuesta));

// El objeto guardado en la sesión sí lleva la respuesta; el mostrable, no.
// Si alguien devolviera el desafío entero por error, esto lo cantaría.
probar("El desafío completo y el mostrable son objetos distintos",
  captcha.parteMostrable(soloTexto) !== soloTexto);

/* --- El dibujo no se puede leer, hay que mirarlo ---------------------------- */
console.log("\n=== El marcado no delata la respuesta ===");

for (const tipo of ["texto", "aritmetica"]) {
  const desafio = captcha.crearDesafio(tipo);
  probar(`[${tipo}] el SVG no usa <text> (un bot lo leería con una regex)`,
    !desafio.svg.includes("<text") && !desafio.svg.includes("<tspan"));
  probar(`[${tipo}] el SVG solo dibuja polilíneas, curvas y puntos`,
    desafio.svg.includes("<polyline"));
}

const conFiguras = captcha.crearDesafio("figuras");
probar("[figuras] hay nueve celdas", conFiguras.celdas.length === 9);

const cantidadesDePuntos = new Set(conFiguras.celdas.map((svg) => {
  const puntos = /points="([^"]+)"/.exec(svg);
  return puntos ? puntos[1].trim().split(/\s+/).length : -1;
}));
probar("[figuras] las nueve son polígonos con el mismo número de puntos",
  cantidadesDePuntos.size === 1 && !cantidadesDePuntos.has(-1));
probar("[figuras] ninguna celda dice qué figura es",
  conFiguras.celdas.every((svg) =>
    !/triangulo|cuadrado|circulo|<circle|<rect[^>]*x=/.test(svg)));

/* --- Verificación ---------------------------------------------------------- */
console.log("\n=== Verificación de respuestas ===");

const texto = captcha.crearDesafio("texto");
probar("[texto] la respuesta correcta se acepta", captcha.verificar(texto, texto.respuesta));
probar("[texto] en minúsculas también", captcha.verificar(texto, texto.respuesta.toLowerCase()));
probar("[texto] con espacios sueltos también",
  captcha.verificar(texto, " " + texto.respuesta.split("").join(" ") + " "));
probar("[texto] una respuesta distinta se rechaza", !captcha.verificar(texto, "ZZZZZ"));
probar("[texto] una respuesta vacía se rechaza", !captcha.verificar(texto, ""));
probar("[texto] la respuesta a medias se rechaza",
  !captcha.verificar(texto, texto.respuesta.slice(0, 3)));

const suma = captcha.crearDesafio("aritmetica");
probar("[aritmética] el número correcto se acepta", captcha.verificar(suma, suma.respuesta));
probar("[aritmética] el número con espacios se acepta", captcha.verificar(suma, ` ${suma.respuesta} `));
probar("[aritmética] escrito con letras se rechaza", !captcha.verificar(suma, "doce"));
probar("[aritmética] otro número se rechaza",
  !captcha.verificar(suma, String(Number(suma.respuesta) + 1)));

const figuras = captcha.crearDesafio("figuras");
const correctas = figuras.respuesta.split(",").map(Number);
probar("[figuras] la selección correcta se acepta", captcha.verificar(figuras, correctas));
probar("[figuras] el orden de los clics da igual",
  captcha.verificar(figuras, [...correctas].reverse()));
probar("[figuras] repetir un clic no estorba",
  captcha.verificar(figuras, [...correctas, correctas[0]]));
probar("[figuras] también se acepta como cadena",
  captcha.verificar(figuras, correctas.join(",")));
probar("[figuras] quedarse corto se rechaza",
  !captcha.verificar(figuras, correctas.slice(1)));
probar("[figuras] pasarse se rechaza",
  !captcha.verificar(figuras, [...new Set([...correctas, ...[0,1,2,3,4,5,6,7,8]])]));
probar("[figuras] no seleccionar nada se rechaza", !captcha.verificar(figuras, []));
probar("[figuras] índices fuera de la rejilla no cuelan",
  !captcha.verificar(figuras, [99, -3]));

probar("Un desafío sin respuesta guardada nunca se da por bueno",
  !captcha.verificar(null, "loquesea") && !captcha.verificar({ tipo: "texto" }, "loquesea"));

/* --- Reglas de los propios desafíos ---------------------------------------- */
console.log("\n=== Reglas de contenido ===");

probar("El alfabeto evita los caracteres que se confunden (B, I, L, O, Q, S, 0, 1)",
  !/[BILOQS01]/.test(captcha.ALFABETO));
probar("Todos los caracteres del alfabeto tienen trazos dibujables",
  captcha.ALFABETO.split("").every((c) => Array.isArray(captcha.TRAZOS[c])));

let negativos = 0, seleccionesRaras = 0;
for (let i = 0; i < 300; i++) {
  if (Number(captcha.crearDesafio("aritmetica").respuesta) < 0) negativos++;
  const n = captcha.crearDesafio("figuras").respuesta.split(",").length;
  if (n < 2 || n > 4) seleccionesRaras++;
}
probar("La aritmética nunca pide restar hacia un número negativo", negativos === 0);
probar("Las figuras siempre piden entre 2 y 4 celdas", seleccionesRaras === 0);

probar("El desafío de texto tiene la longitud anunciada",
  captcha.crearDesafio("texto").respuesta.length === captcha.LARGO_TEXTO);

// Dos desafíos seguidos del mismo tipo no deben coincidir: si coincidieran,
// bastaría con resolver uno y repetir la respuesta.
let repetidos = 0;
for (let i = 0; i < 50; i++) {
  if (captcha.crearDesafio("texto").respuesta === captcha.crearDesafio("texto").respuesta) repetidos++;
}
probar("Dos desafíos de texto seguidos casi nunca coinciden", repetidos <= 1);

/* --------------------------------------------------------------------------- */
console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);
