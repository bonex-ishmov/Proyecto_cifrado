/* ============================================================================
   captcha.js — Desafíos visuales para verificar que hay una persona
   Universidad El Bosque — Seguridad de la Información — 2026-II

   NO LO EXIGE NINGÚN ENUNCIADO. Es una defensa añadida: un paso intermedio
   entre "las credenciales son correctas" y "la sesión queda abierta", para que
   un programa que ya tenga usuario y contraseña (por ejemplo, robados de otro
   sitio) no pueda entrar sin intervención humana.

   Lo que este módulo NO hace, y conviene decirlo antes de que lo pregunten:
   no frena la fuerza bruta. Cuando el desafío aparece, el atacante ya acertó
   la contraseña. Quien frena la fuerza bruta sigue siendo el bloqueo por
   cuenta (src/login.js) y el bloqueo por IP (src/fuerzaBruta.js).

   TRES VARIANTES, sorteadas al azar en cada inicio de sesión:

     · texto       — cinco caracteres deformados que hay que transcribir
     · aritmetica  — una operación dibujada que hay que resolver
     · figuras     — nueve formas; hay que hacer clic en las de un tipo

   DECISIÓN TÉCNICA IMPORTANTE: el dibujo es SVG, pero NO contiene texto.
   Un CAPTCHA en SVG con <text>H</text> dentro se rompe con una expresión
   regular: el bot no necesita "ver" nada, lee el marcado. Aquí cada letra se
   traza con segmentos de recta a partir de la tabla TRAZOS, y cada figura es
   un <polygon> de 24 puntos, igual para círculos, cuadrados y triángulos. En
   el marcado solo hay coordenadas con ruido, así que para resolverlo hay que
   interpretar la geometría, no leerla.

   LÍMITE HONESTO: esto detiene a un bot genérico, no a alguien que escriba un
   programa específicamente contra este sitio. Ningún CAPTCHA casero lo hace.
   La defensa de verdad contra el robo de credenciales sería un segundo factor.

   Lo que decide la respuesta (qué letras salen, qué números, qué celdas son
   las correctas) se sortea con crypto.randomInt y no con Math.random, que es
   un generador predecible: conociendo unas cuantas salidas se pueden adivinar
   las siguientes. El ruido decorativo sí usa Math.random, porque no influye en
   la respuesta.
   ============================================================================ */

const { randomInt } = require("node:crypto");

/** Intentos por inicio de sesión pendiente antes de tener que empezar de cero. */
const INTENTOS = 3;

/** Minutos que sobrevive un inicio de sesión a medias. */
const MINUTOS_VIGENCIA = 5;

const TIPOS = ["texto", "aritmetica", "figuras"];

/* --- Alfabeto del desafío de texto -----------------------------------------
   No es el alfabeto español de 27 letras del resto del proyecto: aquí manda la
   legibilidad. Fuera B (se confunde con 8), I y L entre sí, O y 0, S y 5, y la
   Ñ, que además obliga a un teclado español. Quedan 21 letras y 8 cifras.
--------------------------------------------------------------------------- */
const ALFABETO = "ACDEFGHJKMNPRTUVWXYZ2346789";

/** Longitud del desafío de texto. */
const LARGO_TEXTO = 5;

/* --- Tipografía de trazos --------------------------------------------------
   Cada carácter es una lista de polilíneas sobre una rejilla de 4 x 6, con el
   origen arriba a la izquierda. Se dibuja con segmentos porque un <polyline>
   no revela qué letra es; un <text> sí.
--------------------------------------------------------------------------- */
const TRAZOS = {
  A: [[[0,6],[0,2],[2,0],[4,2],[4,6]], [[0,4],[4,4]]],
  C: [[[4,1],[3,0],[1,0],[0,1],[0,5],[1,6],[3,6],[4,5]]],
  D: [[[0,0],[0,6],[3,6],[4,5],[4,1],[3,0],[0,0]]],
  E: [[[4,0],[0,0],[0,6],[4,6]], [[0,3],[3,3]]],
  F: [[[4,0],[0,0],[0,6]], [[0,3],[3,3]]],
  G: [[[4,1],[3,0],[1,0],[0,1],[0,5],[1,6],[3,6],[4,5],[4,3],[2,3]]],
  H: [[[0,0],[0,6]], [[4,0],[4,6]], [[0,3],[4,3]]],
  J: [[[4,0],[4,5],[3,6],[1,6],[0,5]]],
  K: [[[0,0],[0,6]], [[4,0],[0,3],[4,6]]],
  M: [[[0,6],[0,0],[2,3],[4,0],[4,6]]],
  N: [[[0,6],[0,0],[4,6],[4,0]]],
  P: [[[0,6],[0,0],[3,0],[4,1],[4,2],[3,3],[0,3]]],
  R: [[[0,6],[0,0],[3,0],[4,1],[4,2],[3,3],[0,3]], [[2,3],[4,6]]],
  T: [[[0,0],[4,0]], [[2,0],[2,6]]],
  U: [[[0,0],[0,5],[1,6],[3,6],[4,5],[4,0]]],
  V: [[[0,0],[2,6],[4,0]]],
  W: [[[0,0],[1,6],[2,2],[3,6],[4,0]]],
  X: [[[0,0],[4,6]], [[4,0],[0,6]]],
  Y: [[[0,0],[2,3],[4,0]], [[2,3],[2,6]]],
  Z: [[[0,0],[4,0],[0,6],[4,6]]],
  2: [[[0,1],[1,0],[3,0],[4,1],[4,2],[0,6],[4,6]]],
  3: [[[0,0],[4,0],[2,3],[4,4],[4,5],[3,6],[1,6],[0,5]]],
  4: [[[3,6],[3,0],[0,4],[4,4]]],
  5: [[[4,0],[0,0],[0,2],[3,2],[4,3],[4,5],[3,6],[1,6],[0,5]]],
  6: [[[4,0],[1,0],[0,1],[0,5],[1,6],[3,6],[4,5],[4,4],[3,3],[0,3]]],
  7: [[[0,0],[4,0],[1,6]]],
  8: [[[1,3],[0,2],[0,1],[1,0],[3,0],[4,1],[4,2],[3,3],[1,3],[0,4],[0,5],[1,6],[3,6],[4,5],[4,4],[3,3]]],
  9: [[[0,6],[3,6],[4,5],[4,1],[3,0],[1,0],[0,1],[0,2],[1,3],[4,3]]],
  "+": [[[0,3],[4,3]], [[2,1],[2,5]]],
  "-": [[[0,3],[4,3]]],
  "x": [[[0,1],[4,5]], [[4,1],[0,5]]],
  "=": [[[0,2],[4,2]], [[0,4],[4,4]]],
  "?": [[[0,1],[1,0],[3,0],[4,1],[4,2],[2,3],[2,4]], [[2,6],[2,6]]]
};

/** Colores oscuros para los trazos. Varían para estorbar la umbralización. */
const TINTAS = ["#1d3f34", "#2a3f6b", "#6b2a3f", "#4a3a1d", "#2f2f2f", "#3f2a6b"];

/* --- Sorteo ---------------------------------------------------------------- */

/** Entero en [min, max], sorteado con el generador criptográfico. */
const ent = (min, max) => min + randomInt(max - min + 1);

/** Elemento al azar de una lista, con el generador criptográfico. */
const elegir = (lista) => lista[randomInt(lista.length)];

/** Ruido decorativo: no decide nada, así que Math.random basta. */
const ruido = (min, max) => min + Math.random() * (max - min);

/* --- Dibujo ---------------------------------------------------------------- */

const num = (n) => Math.round(n * 10) / 10;

/**
 * Convierte un carácter en polilíneas SVG ya deformadas.
 * La rotación se aplica a mano sobre cada punto, no con un transform="rotate()":
 * un transform es una instrucción que un programa puede deshacer en una línea,
 * mientras que unas coordenadas ya giradas y con ruido hay que interpretarlas.
 */
function dibujarGlifo(caracter, izquierda, arriba, escala, angulo, tinta) {
  const trazos = TRAZOS[caracter];
  if (!trazos) return "";

  const cos = Math.cos(angulo), sen = Math.sin(angulo);
  const cx = 2, cy = 3;                       // centro de la rejilla 4 x 6
  let salida = "";

  for (const trazo of trazos) {
    const puntos = trazo.map(([x, y]) => {
      const dx = x - cx, dy = y - cy;
      const gx = cx + dx * cos - dy * sen;
      const gy = cy + dx * sen + dy * cos;
      // El ruido por punto impide reconocer la letra comparando coordenadas
      // exactas contra esta misma tabla.
      return `${num(izquierda + gx * escala + ruido(-1.3, 1.3))},` +
             `${num(arriba + gy * escala + ruido(-1.3, 1.3))}`;
    }).join(" ");

    salida += `<polyline points="${puntos}" fill="none" stroke="${tinta}" ` +
              `stroke-width="${num(ruido(2.2, 3.2))}" stroke-linecap="round" ` +
              `stroke-linejoin="round"/>`;
  }
  return salida;
}

/** Líneas y puntos sueltos sobre toda la imagen, para estorbar el recorte automático. */
function ensuciar(ancho, alto) {
  let salida = "";
  for (let i = 0; i < 5; i++) {
    const x1 = ruido(0, ancho), y1 = ruido(0, alto);
    const x2 = ruido(0, ancho), y2 = ruido(0, alto);
    const cx = ruido(0, ancho), cy = ruido(0, alto);
    salida += `<path d="M${num(x1)},${num(y1)} Q${num(cx)},${num(cy)} ${num(x2)},${num(y2)}" ` +
              `fill="none" stroke="${elegir(TINTAS)}" stroke-width="${num(ruido(0.8, 1.6))}" opacity="0.45"/>`;
  }
  for (let i = 0; i < 45; i++) {
    salida += `<circle cx="${num(ruido(0, ancho))}" cy="${num(ruido(0, alto))}" ` +
              `r="${num(ruido(0.7, 1.8))}" fill="${elegir(TINTAS)}" opacity="0.4"/>`;
  }
  return salida;
}

/** Dibuja una cadena de caracteres deformados y devuelve el SVG completo. */
function svgDeCadena(caracteres) {
  const ESCALA = 7;
  const PASO = 40;
  const MARGEN = 20;
  const ancho = MARGEN * 2 + PASO * caracteres.length;
  const alto = 92;

  let cuerpo = ensuciar(ancho, alto);
  caracteres.forEach((caracter, i) => {
    cuerpo += dibujarGlifo(
      caracter,
      MARGEN + i * PASO + ruido(-3, 3),
      22 + ruido(-7, 7),
      ESCALA * ruido(0.9, 1.15),
      ruido(-0.38, 0.38),                    // ±22 grados
      elegir(TINTAS)
    );
  });
  // Unos puntos por encima, para que las letras no queden siempre "arriba"
  // y un recorte por color no las separe del fondo.
  for (let i = 0; i < 25; i++) {
    cuerpo += `<circle cx="${num(ruido(0, ancho))}" cy="${num(ruido(0, alto))}" ` +
              `r="${num(ruido(0.8, 2))}" fill="${elegir(TINTAS)}" opacity="0.35"/>`;
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${ancho} ${alto}" ` +
         `width="${ancho}" height="${alto}" role="img" aria-label="Imagen del desafío">` +
         `<rect width="${ancho}" height="${alto}" fill="#f4f6f5"/>${cuerpo}</svg>`;
}

/* --- Figuras ---------------------------------------------------------------- */

const FIGURAS = {
  triangulo: { plural: "triángulos", vertices: 3, radio: 44, giroBase: -Math.PI / 2 },
  cuadrado:  { plural: "cuadrados",  vertices: 4, radio: 42, giroBase: Math.PI / 4 },
  circulo:   { plural: "círculos",   vertices: 30, radio: 38, giroBase: 0 }
};

/** Vértices de un polígono regular centrado en (50,50). */
function verticesDe(figura, giro) {
  const { vertices, radio, giroBase } = FIGURAS[figura];
  const salida = [];
  for (let i = 0; i < vertices; i++) {
    const a = giroBase + giro + (2 * Math.PI * i) / vertices;
    salida.push([50 + radio * Math.cos(a), 50 + radio * Math.sin(a)]);
  }
  return salida;
}

/**
 * Reparte `total` puntos a lo largo del contorno cerrado.
 * Así las tres figuras salen como un <polygon> de exactamente 24 puntos: el
 * marcado no delata cuál es cada una, hay que mirar la forma.
 */
function repartir(vertices, total) {
  const lados = vertices.map((p, i) => {
    const q = vertices[(i + 1) % vertices.length];
    return { p, q, largo: Math.hypot(q[0] - p[0], q[1] - p[1]) };
  });
  const perimetro = lados.reduce((s, l) => s + l.largo, 0);

  const puntos = [];
  for (let i = 0; i < total; i++) {
    let recorrido = (perimetro * i) / total;
    for (const lado of lados) {
      if (recorrido <= lado.largo) {
        const t = lado.largo === 0 ? 0 : recorrido / lado.largo;
        puntos.push([
          lado.p[0] + (lado.q[0] - lado.p[0]) * t + ruido(-1.4, 1.4),
          lado.p[1] + (lado.q[1] - lado.p[1]) * t + ruido(-1.4, 1.4)
        ]);
        break;
      }
      recorrido -= lado.largo;
    }
  }
  return puntos;
}

function svgDeFigura(figura) {
  const puntos = repartir(verticesDe(figura, ruido(0, Math.PI * 2)), 24)
    .map(([x, y]) => `${num(x)},${num(y)}`).join(" ");
  const tinta = elegir(TINTAS);

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" ` +
         `width="100%" height="100%" aria-hidden="true">` +
         `<rect width="100" height="100" fill="#f4f6f5"/>` +
         `<polygon points="${puntos}" fill="${tinta}" fill-opacity="0.22" ` +
         `stroke="${tinta}" stroke-width="2.5" stroke-linejoin="round"/></svg>`;
}

/* --- Construcción de cada variante ------------------------------------------ */

function desafioTexto() {
  const caracteres = [];
  for (let i = 0; i < LARGO_TEXTO; i++) caracteres.push(elegir(ALFABETO.split("")));
  return {
    tipo: "texto",
    modo: "texto",
    enunciado: `Escribe los ${LARGO_TEXTO} caracteres que aparecen en la imagen.`,
    svg: svgDeCadena(caracteres),
    respuesta: caracteres.join("")
  };
}

function desafioAritmetica() {
  const operacion = elegir(["+", "-", "x"]);
  let a, b, resultado;

  if (operacion === "+") {
    a = ent(2, 9); b = ent(2, 9); resultado = a + b;
  } else if (operacion === "-") {
    a = ent(5, 9); b = ent(1, a - 1); resultado = a - b;   // nunca negativo
  } else {
    a = ent(2, 9); b = ent(2, 5); resultado = a * b;
  }

  return {
    tipo: "aritmetica",
    modo: "numero",
    enunciado: "Resuelve la operación de la imagen y escribe el resultado.",
    svg: svgDeCadena([String(a), operacion, String(b), "=", "?"]),
    respuesta: String(resultado)
  };
}

function desafioFiguras() {
  const nombres = Object.keys(FIGURAS);
  const buscada = elegir(nombres);
  const otras = nombres.filter((n) => n !== buscada);

  // Entre 2 y 4 aciertos: con menos, acertar al azar sería demasiado fácil;
  // con más, la rejilla se vuelve confusa.
  const cuantas = ent(2, 4);
  const celdas = new Array(9).fill(null);

  const elegidas = new Set();
  while (elegidas.size < cuantas) elegidas.add(randomInt(9));
  for (let i = 0; i < 9; i++) celdas[i] = elegidas.has(i) ? buscada : elegir(otras);

  return {
    tipo: "figuras",
    modo: "seleccion",
    enunciado: `Haz clic en todos los ${FIGURAS[buscada].plural}.`,
    celdas: celdas.map(svgDeFigura),
    respuesta: Array.from(elegidas).sort((x, y) => x - y).join(",")
  };
}

/**
 * Crea un desafío. Sin argumento, sortea la variante.
 * @param {string} [tipo] "texto" | "aritmetica" | "figuras"
 */
function crearDesafio(tipo) {
  const elegido = TIPOS.includes(tipo) ? tipo : elegir(TIPOS);
  if (elegido === "texto") return desafioTexto();
  if (elegido === "aritmetica") return desafioAritmetica();
  return desafioFiguras();
}

/**
 * Lo único que puede salir hacia el navegador. La respuesta se queda en la
 * sesión, en el servidor: si viajara al cliente, aunque fuera cifrada u oculta
 * en un campo, el desafío no serviría absolutamente de nada.
 */
function parteMostrable(desafio) {
  const { tipo, modo, enunciado, svg, celdas } = desafio;
  const publico = { tipo, modo, enunciado };
  if (svg) publico.svg = svg;
  if (celdas) publico.celdas = celdas;
  return publico;
}

/** Deja la respuesta del usuario en la misma forma que la guardada. */
function normalizar(tipo, respuesta) {
  if (tipo === "figuras") {
    const lista = Array.isArray(respuesta) ? respuesta : String(respuesta ?? "").split(",");
    return lista
      .map((n) => Number.parseInt(n, 10))
      .filter((n) => Number.isInteger(n) && n >= 0 && n <= 8)
      .filter((n, i, a) => a.indexOf(n) === i)      // sin repetidos
      .sort((x, y) => x - y)
      .join(",");
  }
  if (tipo === "aritmetica") {
    const n = Number.parseInt(String(respuesta ?? "").trim(), 10);
    return Number.isInteger(n) ? String(n) : "";
  }
  // texto: se perdona el uso de minúsculas y los espacios, no los caracteres.
  return String(respuesta ?? "").toUpperCase().replace(/\s+/g, "");
}

/** @returns {boolean} true solo si la respuesta coincide exactamente. */
function verificar(desafio, respuesta) {
  if (!desafio || typeof desafio.respuesta !== "string") return false;
  const dada = normalizar(desafio.tipo, respuesta);
  return dada !== "" && dada === desafio.respuesta;
}

module.exports = {
  crearDesafio, parteMostrable, verificar, normalizar,
  TIPOS, INTENTOS, MINUTOS_VIGENCIA, ALFABETO, LARGO_TEXTO, TRAZOS
};
