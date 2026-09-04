/* ============================================================================
   pruebas.js  —  Validación contra los ejemplos del documento del taller
   Ejecutar con:  npm test      (o:  node test/pruebas.js)

   No usa librerías de testing: solo Node. Cada fase irá agregando pruebas
   a este mismo archivo.
   ============================================================================ */

const C = require("../public/cripto.js");

/* ---------------------------------------------------------------------------
   Datos de la guía (páginas 4 y 5). Los criptogramas se copian tal cual,
   partidos en varias líneas solo por legibilidad.
--------------------------------------------------------------------------- */
const RETOS = [
  {
    nombre: "Reto 1 — César",
    claro: "Habla sobre la historia de la criptografía desde la antigüedad, mencionando que la " +
           "necesidad de ocultar mensajes ha existido siempre para proteger secretos militares y políticos.",
    cifrado:
      "MFGPFXTGWJPFMNXYTWNFIJPFHWNUYTLWFKNFIJXIJPFFRYNLZJIFIQJRHNTRFRITVZJPFRJHJXNIFIIJ" +
      "THZPYFWQJRXFÑJXMFJCNXYNITXNJQUWJUFWFUWTYJLJWXJHWJYTXQNPNYFWJXDUTPNYNHTX",
    claveGuia: "k = 11",
    claveReal: "k = 5",
    icEsperado: 0.0700,
    tipoEsperado: "monoalfabetico"
  },
  {
    nombre: "Reto 2 — Afín",
    claro: "Explica el análisis de frecuencias y cómo las letras como la E y la A son las más " +
           "comunes en el idioma español, permitiendo romper cifrados monoalfabéticos con relativa facilidad.",
    cifrado:
      "ASGITQHAIHRHITUTUVAFPAQEARQTHUXQBNBIHUIAZPHUQBNBIHAXIHHUBRIHUNHUQBNERAUAR" +
      "AITVTBNHAUGHWBIGAPNTZTARVBPBNGAPQTFPHVBUNBRBHIFHMAZTQBUQBRPAIHZTJHFHQTITV" +
      "HV",
    claveGuia: "a = 5, b = 7",
    claveReal: "a = 5, b = 7",
    icEsperado: 0.0730,
    tipoEsperado: "monoalfabetico"
  },
  {
    nombre: "Reto 3 — Vigenère",
    claro: "Describe la máquina Enigma y cómo Alan Turing logró descifrarla en Bletchley Park, " +
           "cambiando el curso de la Segunda Guerra Mundial gracias al uso de las primeras computadoras electromecánicas.",
    cifrado:
      "PYTGECCIXUNEDOJQNYÑMSGBCOJNSNFBQGOSMZAMSSMPHQNDMRMBVXUFQÑFFXOBMILKBVW" +
      "WBPÑCBQPJFOOOSWBXFONNFKHHEESOFVEUNYZXJEXASEOCBWNFVWBXFONNQVUGFVNNDSYKV" +
      "XNXPVNNFOQWUVBGFGNHJGNN",
    claveGuia: "NUBE",
    claveReal: "NUBE",
    icEsperado: 0.0492,
    tipoEsperado: "polialfabetico"
  }
];

/* ---------------------------------------------------------------------------
   Mini framework de aserciones
--------------------------------------------------------------------------- */
let pasadas = 0;
let falladas = 0;

function probar(descripcion, obtenido, esperado) {
  const ok = obtenido === esperado;
  ok ? pasadas++ : falladas++;
  console.log(`  ${ok ? "OK  " : "FALLA"}  ${descripcion}`);
  if (!ok) {
    console.log(`        esperado: ${esperado}`);
    console.log(`        obtenido: ${obtenido}`);
  }
}

function probarCerca(descripcion, obtenido, esperado, tolerancia) {
  const ok = Math.abs(obtenido - esperado) <= tolerancia;
  ok ? pasadas++ : falladas++;
  console.log(`  ${ok ? "OK  " : "FALLA"}  ${descripcion} (${obtenido.toFixed(4)}, esperado ~${esperado})`);
}

/* ---------------------------------------------------------------------------
   Grupo 1 — Alfabeto y normalización
--------------------------------------------------------------------------- */
console.log("\n=== Alfabeto y normalización ===");
probar("El alfabeto tiene 27 letras", C.N, 27);
probar("La Ñ está en la posición 14", C.indiceDe("Ñ"), 14);
probar("La O corre a la posición 15", C.indiceDe("O"), 15);
probar("letraDe da la vuelta con módulo 27", C.letraDe(27), "A");
probar("mod() nunca devuelve negativos", C.mod(-3, 27), 24);
probar(
  "normalizar quita tildes, signos y espacios pero conserva la Ñ",
  C.normalizar("El ñandú, ¿comió? ¡Sí: 2 veces!"),
  "ELÑANDUCOMIOSIVECES"
);
probar("normalizar con texto vacío", C.normalizar(""), "");

/* ---------------------------------------------------------------------------
   Grupo 2 — Diagnóstico de los tres criptogramas de la guía
--------------------------------------------------------------------------- */
console.log("\n=== Diagnóstico de los criptogramas de la guía ===");
for (const reto of RETOS) {
  console.log(`\n${reto.nombre}  (${reto.cifrado.length} caracteres)`);

  probar(
    "El criptograma solo contiene letras del alfabeto de 27",
    C.normalizar(reto.cifrado),
    reto.cifrado
  );

  const diagnostico = C.clasificarPorIC(reto.cifrado);
  probarCerca("Índice de coincidencia", diagnostico.ic, reto.icEsperado, 0.002);
  probar("Tipo de cifrado detectado", diagnostico.tipo, reto.tipoEsperado);

  const top = C.frecuenciasOrdenadas(reto.cifrado).slice(0, 4);
  console.log("        más frecuentes: " + top.map((f) => `${f.letra}=${f.conteo}`).join("  "));
  console.log(`        confianza del diagnóstico: ${(diagnostico.confianza * 100).toFixed(0)}%`);
  if (reto.claveGuia !== reto.claveReal) {
    console.log(`        AVISO: la guía dice ${reto.claveGuia}, pero la clave real es ${reto.claveReal}`);
  }
}

/* ---------------------------------------------------------------------------
   Grupo 3 — Chi-cuadrado: el texto claro debe parecerse más al español
   que el texto cifrado.
--------------------------------------------------------------------------- */
console.log("\n=== Chi-cuadrado ===");
for (const reto of RETOS) {
  const chiClaro = C.chiCuadrado(reto.claro);
  const chiCifrado = C.chiCuadrado(reto.cifrado);
  probar(
    `${reto.nombre}: el texto claro puntúa mejor que el cifrado`,
    chiClaro < chiCifrado,
    true
  );
  console.log(`        claro=${chiClaro.toFixed(1)}   cifrado=${chiCifrado.toFixed(1)}`);
}

/* ---------------------------------------------------------------------------
   Grupo 4 — Validación de código (punto 1 de "¿Qué se espera como análisis?")
   Se mete el texto original de la guía en el programa y se verifica que el
   criptograma que sale sea IDÉNTICO al del documento.
--------------------------------------------------------------------------- */
console.log("\n=== Validación de código: cifrar los textos originales de la guía ===");

const [CESAR, AFIN, VIGENERE] = RETOS;

probar("César con k = 5 reproduce el criptograma de la guía",
  C.cesarCifrar(CESAR.claro, 5), CESAR.cifrado);

probar("César con k = 11 (el que dice la guía) NO lo reproduce",
  C.cesarCifrar(CESAR.claro, 11) !== CESAR.cifrado, true);

probar("Afín con a = 5, b = 7 reproduce el criptograma de la guía",
  C.afinCifrar(AFIN.claro, 5, 7), AFIN.cifrado);

probar("Vigenère con la clave NUBE reproduce el criptograma de la guía",
  C.vigenereCifrar(VIGENERE.claro, "NUBE"), VIGENERE.cifrado);

console.log("\n=== Descifrado: recuperar el texto original ===");

probar("César descifra el Reto 1",
  C.cesarDescifrar(CESAR.cifrado, 5), C.normalizar(CESAR.claro));

probar("Afín descifra el Reto 2",
  C.afinDescifrar(AFIN.cifrado, 5, 7), C.normalizar(AFIN.claro));

probar("Vigenère descifra el Reto 3",
  C.vigenereDescifrar(VIGENERE.cifrado, "NUBE"), C.normalizar(VIGENERE.claro));

/* ---------------------------------------------------------------------------
   Grupo 5 — Casos generales: la herramienta no puede servir solo para la guía
--------------------------------------------------------------------------- */
console.log("\n=== Casos generales y bordes ===");

const TEXTO_LIBRE = "El señor Muñoz añadió: ¿qué año es? ¡2026!";
const CLARO_LIBRE = C.normalizar(TEXTO_LIBRE); // ELSEÑORMUÑOZAÑADIOQUEAÑOES

probar("César: cifrar y descifrar devuelve el texto normalizado",
  C.cesarDescifrar(C.cesarCifrar(TEXTO_LIBRE, 19), 19), CLARO_LIBRE);

probar("César: k = 32 equivale a k = 5 (módulo 27)",
  C.cesarCifrar(TEXTO_LIBRE, 32), C.cesarCifrar(TEXTO_LIBRE, 5));

probar("César: k = 0 y k = 27 dejan el texto igual",
  C.cesarCifrar(TEXTO_LIBRE, 27), CLARO_LIBRE);

probar("Afín: hay exactamente 18 valores válidos de 'a'",
  C.VALORES_A_VALIDOS.length, 18);

probar("Afín: a = 3 se rechaza por no ser coprimo con 27",
  C.esClaveAfinValida(3), false);

probar("Afín: cifrar con a = 3 lanza un error claro", (() => {
  try { C.afinCifrar(TEXTO_LIBRE, 3, 4); return false; } catch (e) { return true; }
})(), true);

probar("Afín: el inverso de 5 módulo 27 es 11",
  C.inversoModular(5), 11);

probar("Afín: cifrar y descifrar devuelve el texto normalizado, con todos los 'a' válidos",
  C.VALORES_A_VALIDOS.every((a) =>
    C.afinDescifrar(C.afinCifrar(TEXTO_LIBRE, a, 13), a, 13) === CLARO_LIBRE), true);

probar("Afín con a = 1 se comporta como un César",
  C.afinCifrar(TEXTO_LIBRE, 1, 9), C.cesarCifrar(TEXTO_LIBRE, 9));

probar("Vigenère: cifrar y descifrar devuelve el texto normalizado",
  C.vigenereDescifrar(C.vigenereCifrar(TEXTO_LIBRE, "Contraseña"), "Contraseña"), CLARO_LIBRE);

probar("Vigenère: la clave se normaliza, 'Nube' = 'NUBE'",
  C.vigenereCifrar(TEXTO_LIBRE, "Nube"), C.vigenereCifrar(TEXTO_LIBRE, "NUBE"));

probar("Vigenère con clave de una letra es un César",
  C.vigenereCifrar(TEXTO_LIBRE, "F"), C.cesarCifrar(TEXTO_LIBRE, 5));

probar("Vigenère: clave sin letras lanza un error claro", (() => {
  try { C.vigenereCifrar(TEXTO_LIBRE, "123 ---"); return false; } catch (e) { return true; }
})(), true);

probar("Los tres cifrados aceptan texto vacío sin romperse",
  C.cesarCifrar("", 5) + C.afinCifrar("", 5, 7) + C.vigenereCifrar("", "NUBE"), "");

/* ---------------------------------------------------------------------------
   Grupo 6 — Criptoanálisis de los tres retos de la guía, SIN darle la clave
   al programa. Es el punto 2 de "¿Qué se espera como análisis?".
--------------------------------------------------------------------------- */
console.log("\n=== Criptoanálisis a ciegas de los retos de la guía ===");

for (const reto of RETOS) {
  const r = C.analizar(reto.cifrado);
  console.log(`\n${reto.nombre}`);
  console.log(`        detectado: ${r.resultado.metodo}   ${r.resultado.clave}   chi²=${r.resultado.chi.toFixed(1)}`);
  probar("Recupera el texto original", r.resultado.textoDescifrado, C.normalizar(reto.claro));
}

probar("Reto 1: el ataque encuentra k = 5", C.atacarCesar(CESAR.cifrado).mejor.clave, 5);

const ecuaciones = C.atacarAfinEcuaciones(AFIN.cifrado);
probar("Reto 2: las ecuaciones dan a = 5, b = 7",
  `${ecuaciones.mejor.clave.a}-${ecuaciones.mejor.clave.b}`, "5-7");
probar("Reto 2: la hipótesis ganadora NO es la que sugiere la guía (E → más frecuente)",
  ecuaciones.mejor.supuesto, "A → H y E → A");
probar("Reto 2: la fuerza bruta llega a la misma clave",
  C.atacarAfinFuerzaBruta(AFIN.cifrado).mejor.claveTexto, "a = 5, b = 7");

const vig = C.atacarVigenere(VIGENERE.cifrado);
probar("Reto 3: Kasiski + IC por columnas dan longitud 4", vig.longitudUsada, 4);
probar("Reto 3: la clave hallada es NUBE", vig.mejor.clave, "NUBE");

/* ---------------------------------------------------------------------------
   Grupo 7 — Casos generales: cifrar un texto propio y romperlo a ciegas.
   Este es el grupo que demuestra que la herramienta no está hecha a la medida
   de los ejemplos del documento.
--------------------------------------------------------------------------- */
console.log("\n=== Criptoanálisis a ciegas de textos propios ===");

const TEXTO_LARGO =
  "La seguridad de la informacion no depende de mantener en secreto el algoritmo sino de " +
  "proteger adecuadamente la clave utilizada, principio que se conoce desde el siglo diecinueve " +
  "gracias al trabajo del linguista holandes Auguste Kerckhoffs. Los cifrados clasicos fueron " +
  "utiles durante siglos porque el analisis manual resultaba lento y costoso, pero hoy cualquier " +
  "computador personal recorre todo su espacio de claves en fracciones de segundo, de modo que su " +
  "valor es unicamente didactico. Estudiarlos permite entender por que la estadistica del lenguaje " +
  "es el punto debil de la sustitucion y por que los sistemas modernos buscan que la salida cifrada " +
  "sea indistinguible de una secuencia aleatoria.";

const CLARO_LARGO = C.normalizar(TEXTO_LARGO);

function romper(descripcion, criptograma, metodoEsperado, claveEsperada) {
  const r = C.analizar(criptograma);
  probar(`${descripcion}: recupera el texto`, r.resultado.textoDescifrado, CLARO_LARGO);
  probar(`${descripcion}: identifica el método (${metodoEsperado})`, r.resultado.metodo, metodoEsperado);
  probar(`${descripcion}: encuentra la clave (${claveEsperada})`, r.resultado.clave, claveEsperada);
}

romper("César k = 22", C.cesarCifrar(TEXTO_LARGO, 22), "César", "k = 22");
romper("Afín a = 20, b = 3", C.afinCifrar(TEXTO_LARGO, 20, 3), "Afín", "a = 20, b = 3");
romper("Vigenère MURCIELAGO", C.vigenereCifrar(TEXTO_LARGO, "MURCIELAGO"), "Vigenère", "clave = MURCIELAGO");

const vigLargo = C.atacarVigenere(C.vigenereCifrar(TEXTO_LARGO, "MURCIELAGO"));
probar("Vigenère: detecta longitud de clave 10", vigLargo.longitudUsada, 10);
probar("Vigenère: no se queda con un múltiplo de la longitud (clave sin repetir)",
  C.reducirClave("NUBENUBENUBE"), "NUBE");

probar("Se puede forzar el método aunque el IC diga otra cosa",
  C.analizar(CESAR.cifrado, { metodo: "afin" }).resultado.metodo, "Afín");

probar("Un texto sin letras se rechaza con un error claro", (() => {
  try { C.analizar("1234 !!"); return false; } catch (e) { return true; }
})(), true);

/* ---------------------------------------------------------------------------
   Resumen
--------------------------------------------------------------------------- */
console.log(`\n----------------------------------------`);
console.log(`Pruebas pasadas: ${pasadas}   falladas: ${falladas}`);
console.log(`----------------------------------------\n`);
process.exit(falladas === 0 ? 0 : 1);

module.exports = { RETOS };
