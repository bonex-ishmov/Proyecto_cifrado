/* ============================================================================
   cripto.js  —  Núcleo criptográfico del Taller de Cifrado Clásico
   Universidad El Bosque — Seguridad de la Información — 2026-II

   Este archivo NO depende del navegador ni de Node: es JavaScript puro.
   Se carga con <script> en la página y con require() en las pruebas.

   FASE 1: alfabeto, normalización, frecuencias, Índice de Coincidencia (IC)
           y chi-cuadrado.
   ============================================================================ */

/* ---------------------------------------------------------------------------
   1. ALFABETO
   El documento dice "A-Z (27 caracteres)", pero A-Z son 26 letras.
   Los criptogramas de la guía contienen Ñ y solo descifran correctamente
   con el alfabeto español de 27 letras (Ñ en la posición 14).
   Toda la aritmética del taller es módulo 27.
--------------------------------------------------------------------------- */
const ALFABETO = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
const N = ALFABETO.length; // 27

/** Módulo que siempre devuelve un resultado positivo (-3 % 27 daría -3 en JS). */
function mod(a, m) {
  return ((a % m) + m) % m;
}

/** Letra -> número (A=0, B=1, ..., N=13, Ñ=14, O=15, ..., Z=26). Devuelve -1 si no pertenece. */
function indiceDe(letra) {
  return ALFABETO.indexOf(letra);
}

/** Número -> letra. Aplica módulo, así que acepta índices fuera de rango. */
function letraDe(numero) {
  return ALFABETO[mod(numero, N)];
}

/* ---------------------------------------------------------------------------
   2. NORMALIZACIÓN
   Reglas del punto 1 del documento: mayúsculas, sin espacios, sin signos,
   sin tildes. La Ñ SÍ se conserva.

   Truco: normalize("NFD") separa una letra de su tilde (Á -> A + ´), pero
   también separaría Ñ -> N + ~, que es justo lo que no queremos. Por eso la
   Ñ se protege con un carácter centinela antes de quitar los acentos.
--------------------------------------------------------------------------- */
function normalizar(texto) {
  if (!texto) return "";
  const conCentinela = texto.toUpperCase().replace(/Ñ/g, "\u0001");
  const sinTildes = conCentinela.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  return sinTildes.replace(/\u0001/g, "Ñ").replace(/[^A-ZÑ]/g, "");
}

/* ---------------------------------------------------------------------------
   3. TABLA DE FRECUENCIAS DEL ESPAÑOL
   Base: tabla del punto 4 del documento. Dos ajustes:
     a) La tabla del PDF no incluye la Ñ, pero la necesitamos para trabajar
        sobre 27 letras. Se le asigna 0.10 %.
     b) La tabla del PDF suma 100.24 %, no 100 %. Se renormalizó todo para
        que sume exactamente 100 %, requisito del chi-cuadrado.
   Ambos ajustes son decisiones técnicas, no vienen del enunciado.
--------------------------------------------------------------------------- */
const FRECUENCIAS_ESPANOL = {
  A: 12.500, B: 1.417, C: 4.669, D: 5.846, E: 13.647, F: 0.688,
  G: 1.008,  H: 0.698, I: 6.235, J: 0.439, K: 0.020,  L: 4.958,
  M: 3.142,  N: 6.694, Ñ: 0.100, O: 8.659, P: 2.504,  Q: 0.878,
  R: 6.854,  S: 7.961, T: 4.619, U: 3.921, V: 0.898,  W: 0.010,
  X: 0.219,  Y: 0.898, Z: 0.519
};

/* IC teórico de un texto en español y de un texto totalmente aleatorio.
   OJO: con 27 letras el azar da 1/27 = 0.0370 (con 26 daría 0.0385).
   El documento habla de 0.038–0.045 para Vigenère; los ejemplos reales
   de la guía dan ~0.049, así que aquí NO usamos rangos fijos sino cercanía. */
const IC_ESPANOL = 0.077;
const IC_ALEATORIO = 1 / N; // 0.037037...

/* ---------------------------------------------------------------------------
   4. CONTEO DE FRECUENCIAS
--------------------------------------------------------------------------- */
/**
 * Cuenta cuántas veces aparece cada letra del alfabeto en el texto.
 * @returns {{conteo:Object, porcentaje:Object, total:number}}
 */
function contarFrecuencias(texto) {
  const limpio = normalizar(texto);
  const conteo = {};
  const porcentaje = {};

  for (const letra of ALFABETO) conteo[letra] = 0;
  for (const letra of limpio) conteo[letra]++;

  const total = limpio.length;
  for (const letra of ALFABETO) {
    porcentaje[letra] = total === 0 ? 0 : (conteo[letra] * 100) / total;
  }
  return { conteo, porcentaje, total };
}

/**
 * Lista de letras ordenadas de más a menos frecuente.
 * La usará el ataque por ecuaciones del Cifrado Afín (Fase 3).
 * @returns {Array<{letra:string, conteo:number, porcentaje:number}>}
 */
function frecuenciasOrdenadas(texto) {
  const { conteo, porcentaje } = contarFrecuencias(texto);
  return ALFABETO.split("")
    .map((letra) => ({ letra, conteo: conteo[letra], porcentaje: porcentaje[letra] }))
    .sort((a, b) => b.conteo - a.conteo || ALFABETO.indexOf(a.letra) - ALFABETO.indexOf(b.letra));
}

/* ---------------------------------------------------------------------------
   5. ÍNDICE DE COINCIDENCIA
   Fórmula del punto 3 del documento:  IC = Σ fi(fi-1) / N(N-1)
   Mide la probabilidad de que dos letras tomadas al azar del texto sean
   iguales. Un cifrado monoalfabético conserva el IC del idioma; uno
   polialfabético lo aplana hacia el valor aleatorio.
--------------------------------------------------------------------------- */
function indiceCoincidencia(texto) {
  const { conteo, total } = contarFrecuencias(texto);
  if (total < 2) return 0;

  let suma = 0;
  for (const letra of ALFABETO) suma += conteo[letra] * (conteo[letra] - 1);
  return suma / (total * (total - 1));
}

/* ---------------------------------------------------------------------------
   6. CHI-CUADRADO
   Mide qué tan lejos está la distribución de letras de un texto respecto al
   español. Valor bajo = el texto parece español. Es el criterio automático
   con el que, en la Fase 3, se elegirá la clave correcta entre todas las
   candidatas de fuerza bruta.
--------------------------------------------------------------------------- */
function chiCuadrado(texto) {
  const { conteo, total } = contarFrecuencias(texto);
  if (total === 0) return Infinity;

  let suma = 0;
  for (const letra of ALFABETO) {
    const esperado = (total * FRECUENCIAS_ESPANOL[letra]) / 100;
    const diferencia = conteo[letra] - esperado;
    suma += (diferencia * diferencia) / esperado;
  }
  return suma;
}

/* ---------------------------------------------------------------------------
   7. DIAGNÓSTICO: ¿monoalfabético o polialfabético?
   En vez de rangos fijos, se compara a cuál de los dos valores teóricos
   se parece más el IC medido. Devuelve además la confianza para que la
   interfaz pueda advertir cuando el texto es corto y el diagnóstico dudoso.
--------------------------------------------------------------------------- */
function clasificarPorIC(texto) {
  const ic = indiceCoincidencia(texto);
  const distMono = Math.abs(ic - IC_ESPANOL);
  const distPoli = Math.abs(ic - IC_ALEATORIO);
  const esMono = distMono <= distPoli;

  // 0 = justo en la mitad entre ambos valores; 1 = clavado en uno de ellos.
  const separacion = IC_ESPANOL - IC_ALEATORIO;
  const confianza = Math.min(1, Math.abs(distPoli - distMono) / separacion);

  return {
    ic,
    tipo: esMono ? "monoalfabetico" : "polialfabetico",
    candidatos: esMono ? ["César", "Afín"] : ["Vigenère"],
    confianza,
    referencias: { espanol: IC_ESPANOL, aleatorio: IC_ALEATORIO },
    mensaje: esMono
      ? `IC = ${ic.toFixed(4)}, cercano a ${IC_ESPANOL} (español sin mezclar): el cifrado conserva la estadística del idioma, así que es monoalfabético (César o Afín).`
      : `IC = ${ic.toFixed(4)}, cercano a ${IC_ALEATORIO.toFixed(4)} (azar sobre 27 letras): la estadística del idioma está aplanada, así que es polialfabético (Vigenère).`
  };
}

/* ===========================================================================
   FASE 2 — LOS TRES CIFRADOS, EN AMBOS SENTIDOS
   =========================================================================== */

/* ---------------------------------------------------------------------------
   8. CIFRADO CÉSAR
   Fórmula del documento:  C = (m + b) mod 27
   El desplazamiento se toma módulo 27, así que k = 32 equivale a k = 5.
--------------------------------------------------------------------------- */
function cesarCifrar(texto, k) {
  const limpio = normalizar(texto);
  const desplazamiento = mod(Number(k), N);
  let salida = "";
  for (const letra of limpio) salida += letraDe(indiceDe(letra) + desplazamiento);
  return salida;
}

function cesarDescifrar(texto, k) {
  // Descifrar es cifrar con el desplazamiento contrario.
  return cesarCifrar(texto, -Number(k));
}

/* ---------------------------------------------------------------------------
   9. CIFRADO AFÍN
   Fórmula del documento:  C = ((a * m) + b) mod 27
   Para descifrar hay que despejar m:  m = a⁻¹ * (C - b) mod 27
   Eso solo es posible si a tiene inverso, es decir si mcd(a, 27) = 1.
   Como 27 = 3³, basta con que 'a' no sea múltiplo de 3: quedan 18 valores.
--------------------------------------------------------------------------- */
function mcd(a, b) {
  while (b !== 0) [a, b] = [b, a % b];
  return Math.abs(a);
}

/** ¿Es 'a' una clave válida para el Afín? (coprimo con 27) */
function esClaveAfinValida(a) {
  return Number.isInteger(Number(a)) && mcd(mod(Number(a), N), N) === 1;
}

/** Los 18 valores de 'a' admisibles. Se calculan, no se escriben a mano. */
const VALORES_A_VALIDOS = Array.from({ length: N }, (_, i) => i).filter(esClaveAfinValida);

/**
 * Inverso modular por búsqueda directa: el x tal que (a * x) mod 27 = 1.
 * Con 27 posibilidades no hace falta el algoritmo de Euclides extendido.
 */
function inversoModular(a, m = N) {
  const base = mod(Number(a), m);
  for (let x = 1; x < m; x++) {
    if (mod(base * x, m) === 1) return x;
  }
  throw new Error(`${a} no tiene inverso módulo ${m}: mcd(${a}, ${m}) ≠ 1.`);
}

function afinCifrar(texto, a, b) {
  if (!esClaveAfinValida(a)) {
    throw new Error(`a = ${a} no es válida: debe ser coprima con 27 (no múltiplo de 3).`);
  }
  const limpio = normalizar(texto);
  const A = mod(Number(a), N);
  const B = mod(Number(b), N);
  let salida = "";
  for (const letra of limpio) salida += letraDe(A * indiceDe(letra) + B);
  return salida;
}

function afinDescifrar(texto, a, b) {
  const inverso = inversoModular(a); // lanza error si 'a' no sirve
  const limpio = normalizar(texto);
  const B = mod(Number(b), N);
  let salida = "";
  for (const letra of limpio) salida += letraDe(inverso * (indiceDe(letra) - B));
  return salida;
}

/* ---------------------------------------------------------------------------
   10. CIFRADO DE VIGENÈRE
   Cada letra se desplaza según la letra de la clave que le toque; la clave
   se repite cíclicamente. Es un César distinto por cada posición de la clave.
   La clave se normaliza igual que el texto, así que "Nube" y "NUBE" son lo mismo.
--------------------------------------------------------------------------- */
function normalizarClave(clave) {
  const limpia = normalizar(clave);
  if (limpia.length === 0) {
    throw new Error("La clave de Vigenère debe tener al menos una letra del alfabeto.");
  }
  return limpia;
}

function vigenereCifrar(texto, clave) {
  const limpio = normalizar(texto);
  const k = normalizarClave(clave);
  let salida = "";
  for (let i = 0; i < limpio.length; i++) {
    salida += letraDe(indiceDe(limpio[i]) + indiceDe(k[i % k.length]));
  }
  return salida;
}

function vigenereDescifrar(texto, clave) {
  const limpio = normalizar(texto);
  const k = normalizarClave(clave);
  let salida = "";
  for (let i = 0; i < limpio.length; i++) {
    salida += letraDe(indiceDe(limpio[i]) - indiceDe(k[i % k.length]));
  }
  return salida;
}

/* ===========================================================================
   FASE 3 — LOS ATAQUES
   Criterio común: cuando hay muchas claves candidatas, se descifra con todas
   y se ordenan por chi-cuadrado. La de menor chi² es la que más se parece al
   español. Así el programa decide solo, sin que nadie lea cada intento.
   =========================================================================== */

/* ---------------------------------------------------------------------------
   11. ATAQUE AL CÉSAR — FUERZA BRUTA
   27 desplazamientos posibles (26 útiles más la identidad). Se prueban todos.
--------------------------------------------------------------------------- */
function atacarCesar(texto) {
  const limpio = normalizar(texto);
  const candidatos = [];

  for (let k = 0; k < N; k++) {
    const descifrado = cesarDescifrar(limpio, k);
    candidatos.push({ clave: k, claveTexto: `k = ${k}`, descifrado, chi: chiCuadrado(descifrado) });
  }
  candidatos.sort((a, b) => a.chi - b.chi);

  return {
    metodo: "César",
    ataque: "Fuerza bruta sobre los 27 desplazamientos",
    intentos: candidatos.length,
    mejor: candidatos[0],
    candidatos
  };
}

/* ---------------------------------------------------------------------------
   12. ATAQUE AL AFÍN — A) POR ECUACIONES (el que pide el documento)
   Se supone que las letras más frecuentes del criptograma corresponden a las
   más frecuentes del español, y se arma el sistema:
        c₁ = (a·p₁ + b) mod 27
        c₂ = (a·p₂ + b) mod 27
   Restando:  a = (c₁ - c₂) · (p₁ - p₂)⁻¹ mod 27,  y luego  b = c₁ - a·p₁.

   OJO: el documento sugiere una sola hipótesis ("la más frecuente es la E").
   En su propio Reto 2 eso falla: la letra más frecuente del criptograma es la
   H y corresponde a la A, no a la E. Por eso aquí se prueban varias hipótesis
   y se escoge la ganadora por chi-cuadrado.
--------------------------------------------------------------------------- */
const LETRAS_FRECUENTES_ESPANOL = ["E", "A", "O", "S"];

function atacarAfinEcuaciones(texto) {
  const limpio = normalizar(texto);
  const top = frecuenciasOrdenadas(limpio).slice(0, 3).map((f) => f.letra);
  const hipotesis = [];
  const vistas = new Set();

  for (const c1 of top) {
    for (const c2 of top) {
      if (c1 === c2) continue;
      for (const p1 of LETRAS_FRECUENTES_ESPANOL) {
        for (const p2 of LETRAS_FRECUENTES_ESPANOL) {
          if (p1 === p2) continue;

          const difClaro = mod(indiceDe(p1) - indiceDe(p2), N);
          if (mcd(difClaro, N) !== 1) continue; // el sistema no se puede resolver

          const a = mod(mod(indiceDe(c1) - indiceDe(c2), N) * inversoModular(difClaro), N);
          if (!esClaveAfinValida(a)) continue; // 'a' inservible: no tendría inverso

          const b = mod(indiceDe(c1) - a * indiceDe(p1), N);
          const firma = `${a}-${b}`;
          if (vistas.has(firma)) continue;
          vistas.add(firma);

          const descifrado = afinDescifrar(limpio, a, b);
          hipotesis.push({
            clave: { a, b },
            claveTexto: `a = ${a}, b = ${b}`,
            supuesto: `${p1} → ${c1} y ${p2} → ${c2}`,
            sistema: `${indiceDe(c1)} = (a·${indiceDe(p1)} + b) mod 27 ; ${indiceDe(c2)} = (a·${indiceDe(p2)} + b) mod 27`,
            descifrado,
            chi: chiCuadrado(descifrado)
          });
        }
      }
    }
  }
  hipotesis.sort((a, b) => a.chi - b.chi);

  return {
    metodo: "Afín",
    ataque: "Sistema de ecuaciones con las letras más frecuentes",
    letrasMasFrecuentes: top,
    intentos: hipotesis.length,
    mejor: hipotesis[0] || null,
    candidatos: hipotesis
  };
}

/* ---------------------------------------------------------------------------
   12. ATAQUE AL AFÍN — B) FUERZA BRUTA (red de seguridad)
   18 valores válidos de 'a' × 27 de 'b' = 486 claves. Es barato y garantiza
   encontrar la clave aunque las hipótesis de frecuencias fallen todas.
--------------------------------------------------------------------------- */
function atacarAfinFuerzaBruta(texto) {
  const limpio = normalizar(texto);
  const candidatos = [];

  for (const a of VALORES_A_VALIDOS) {
    for (let b = 0; b < N; b++) {
      const descifrado = afinDescifrar(limpio, a, b);
      candidatos.push({
        clave: { a, b },
        claveTexto: `a = ${a}, b = ${b}`,
        descifrado,
        chi: chiCuadrado(descifrado)
      });
    }
  }
  candidatos.sort((a, b) => a.chi - b.chi);

  return {
    metodo: "Afín",
    ataque: "Fuerza bruta sobre las 486 claves válidas",
    intentos: candidatos.length,
    mejor: candidatos[0],
    candidatos: candidatos.slice(0, 10)
  };
}

/* ---------------------------------------------------------------------------
   13. ATAQUE A VIGENÈRE
   Paso 1: Kasiski. Buscar secuencias repetidas y factorizar las distancias
           entre ellas; la longitud de la clave suele dividir a esas distancias.
   Paso 2: IC por columnas. Partir el texto en L columnas; si L es correcta,
           cada columna es un César y su IC sube al del español (~0.077).
   Paso 3: resolver cada columna como un César independiente.
--------------------------------------------------------------------------- */

/** Secuencias repetidas de 3+ letras y las distancias entre sus apariciones. */
function kasiski(texto, longitudMinima = 3) {
  const limpio = normalizar(texto);
  const posiciones = {};

  for (let L = longitudMinima; L <= longitudMinima + 2; L++) {
    for (let i = 0; i + L <= limpio.length; i++) {
      const trozo = limpio.slice(i, i + L);
      (posiciones[trozo] = posiciones[trozo] || []).push(i);
    }
  }

  const repeticiones = [];
  const votos = {}; // divisor -> cuántas distancias lo tienen

  for (const [trozo, lista] of Object.entries(posiciones)) {
    if (lista.length < 2) continue;
    const distancias = [];
    for (let i = 1; i < lista.length; i++) distancias.push(lista[i] - lista[i - 1]);
    repeticiones.push({ secuencia: trozo, posiciones: lista, distancias });

    for (const d of distancias) {
      for (let divisor = 2; divisor <= Math.min(20, d); divisor++) {
        if (d % divisor === 0) votos[divisor] = (votos[divisor] || 0) + 1;
      }
    }
  }

  const divisores = Object.entries(votos)
    .map(([longitud, votos]) => ({ longitud: Number(longitud), votos }))
    .sort((a, b) => b.votos - a.votos || a.longitud - b.longitud);

  return { repeticiones: repeticiones.slice(0, 15), divisores };
}

/** IC promedio de las L columnas. Si L es la longitud real, sube a ~0.077. */
function icPorColumnas(texto, L) {
  const limpio = normalizar(texto);
  const columnas = Array.from({ length: L }, () => "");
  for (let i = 0; i < limpio.length; i++) columnas[i % L] += limpio[i];

  const ics = columnas.map(indiceCoincidencia);
  return { columnas, ics, promedio: ics.reduce((s, v) => s + v, 0) / L };
}

/**
 * Longitud de clave más probable. Se prefiere la MÁS CORTA que ya alcanza un
 * IC de idioma, porque cualquier múltiplo suyo también lo alcanza (si la clave
 * es NUBE, L = 8 también "funciona" pero da la clave repetida NUBENUBE).
 */
function longitudProbable(texto, maximo = 16, umbral = 0.065) {
  const limpio = normalizar(texto);
  const tope = Math.max(1, Math.min(maximo, Math.floor(limpio.length / 12)));
  const tabla = [];

  for (let L = 1; L <= tope; L++) {
    tabla.push({ longitud: L, ic: icPorColumnas(limpio, L).promedio });
  }
  const suficientes = tabla.filter((f) => f.ic >= umbral);
  const elegida = suficientes.length
    ? suficientes[0].longitud
    : tabla.slice().sort((a, b) => b.ic - a.ic)[0].longitud;

  return { longitud: elegida, tabla };
}

/**
 * Desplazamiento de una columna. Con columnas cortas el chi-cuadrado es
 * inestable, así que se usa correlación: se busca el giro que mejor alinea
 * las frecuencias de la columna con las del español.
 */
function mejorDesplazamientoColumna(columna) {
  const { conteo, total } = contarFrecuencias(columna);
  const puntajes = [];

  for (let k = 0; k < N; k++) {
    let correlacion = 0;
    for (let i = 0; i < N; i++) {
      const letraCifrada = letraDe(i);
      const letraClara = letraDe(i - k);
      correlacion += (conteo[letraCifrada] / (total || 1)) * FRECUENCIAS_ESPANOL[letraClara];
    }
    puntajes.push({ k, letra: letraDe(k), correlacion });
  }
  puntajes.sort((a, b) => b.correlacion - a.correlacion);
  return puntajes;
}

/** Si la clave hallada es un patrón repetido (NUBENUBE), se reduce a NUBE. */
function reducirClave(clave) {
  for (let L = 1; L <= clave.length / 2; L++) {
    if (clave.length % L !== 0) continue;
    const patron = clave.slice(0, L);
    if (patron.repeat(clave.length / L) === clave) return patron;
  }
  return clave;
}

function atacarVigenere(texto, longitudForzada = null) {
  const limpio = normalizar(texto);
  const pistas = kasiski(limpio);
  const analisisLongitud = longitudProbable(limpio);
  const L = longitudForzada ? Number(longitudForzada) : analisisLongitud.longitud;

  const { columnas } = icPorColumnas(limpio, L);
  const detalleColumnas = columnas.map((columna, i) => {
    const puntajes = mejorDesplazamientoColumna(columna);
    return {
      indice: i,
      longitud: columna.length,
      ic: indiceCoincidencia(columna),
      letraClave: puntajes[0].letra,
      desplazamiento: puntajes[0].k,
      alternativas: puntajes.slice(0, 3)
    };
  });

  const claveCruda = detalleColumnas.map((c) => c.letraClave).join("");
  const clave = reducirClave(claveCruda);
  const descifrado = vigenereDescifrar(limpio, clave);

  return {
    metodo: "Vigenère",
    ataque: "Kasiski + IC por columnas + un César por columna",
    kasiski: pistas,
    longitudes: analisisLongitud.tabla,
    longitudUsada: L,
    columnas: detalleColumnas,
    mejor: {
      clave,
      claveTexto: `clave = ${clave}${clave !== claveCruda ? ` (reducida de ${claveCruda})` : ""}`,
      descifrado,
      chi: chiCuadrado(descifrado)
    }
  };
}

/* ---------------------------------------------------------------------------
   14. ANALIZADOR AUTOMÁTICO
   Junta todo: diagnostica por IC, lanza los ataques que correspondan y
   devuelve un único objeto con el resultado y toda la evidencia detrás.
   Si el IC dice monoalfabético se prueban César Y Afín, y gana el de menor
   chi²; el César es un Afín con a = 1, así que compiten en igualdad.
--------------------------------------------------------------------------- */
function analizar(texto, opciones = {}) {
  const limpio = normalizar(texto);
  if (limpio.length === 0) throw new Error("El texto no contiene ninguna letra del alfabeto.");
  if (limpio.length < 2) throw new Error("El texto es demasiado corto para analizarlo.");

  const diagnostico = clasificarPorIC(limpio);
  const forzado = opciones.metodo || null; // "cesar" | "afin" | "vigenere" | null
  const ataques = [];

  const esMono = forzado ? forzado !== "vigenere" : diagnostico.tipo === "monoalfabetico";

  if (forzado === "cesar" || (!forzado && esMono)) ataques.push(atacarCesar(limpio));
  if (forzado === "afin" || (!forzado && esMono)) {
    const porEcuaciones = atacarAfinEcuaciones(limpio);
    const porFuerzaBruta = atacarAfinFuerzaBruta(limpio);
    // Se reporta el ataque que pide la guía, pero si sus hipótesis fallan
    // se toma el de fuerza bruta para no entregar un resultado equivocado.
    const ecuacionesAcerto =
      porEcuaciones.mejor && porEcuaciones.mejor.chi <= porFuerzaBruta.mejor.chi * 1.0001;
    ataques.push({
      ...(ecuacionesAcerto ? porEcuaciones : porFuerzaBruta),
      ecuaciones: porEcuaciones,
      fuerzaBruta: porFuerzaBruta,
      ecuacionesAcerto
    });
  }
  if (forzado === "vigenere" || (!forzado && !esMono)) {
    ataques.push(atacarVigenere(limpio, opciones.longitudClave || null));
  }

  const ganador = ataques.slice().sort((a, b) => a.mejor.chi - b.mejor.chi)[0];

  return {
    textoNormalizado: limpio,
    longitud: limpio.length,
    frecuencias: contarFrecuencias(limpio),
    ordenadas: frecuenciasOrdenadas(limpio),
    diagnostico,
    metodoForzado: forzado,
    ataques,
    resultado: {
      metodo: ganador.metodo,
      clave: ganador.mejor.claveTexto,
      textoDescifrado: ganador.mejor.descifrado,
      chi: ganador.mejor.chi
    }
  };
}

/* ---------------------------------------------------------------------------
   Exportación para Node (pruebas). En el navegador estas funciones quedan
   disponibles como variables globales al cargar el <script>.
--------------------------------------------------------------------------- */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    ALFABETO, N, IC_ESPANOL, IC_ALEATORIO, FRECUENCIAS_ESPANOL,
    mod, indiceDe, letraDe, normalizar,
    contarFrecuencias, frecuenciasOrdenadas,
    indiceCoincidencia, chiCuadrado, clasificarPorIC,
    cesarCifrar, cesarDescifrar,
    mcd, esClaveAfinValida, VALORES_A_VALIDOS, inversoModular,
    afinCifrar, afinDescifrar,
    normalizarClave, vigenereCifrar, vigenereDescifrar,
    atacarCesar, atacarAfinEcuaciones, atacarAfinFuerzaBruta,
    kasiski, icPorColumnas, longitudProbable, mejorDesplazamientoColumna,
    reducirClave, atacarVigenere, analizar
  };
}
