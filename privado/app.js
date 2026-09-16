/* ============================================================================
   app.js — Interfaz de la herramienta
   Solo se ocupa de leer los campos, llamar a cripto.js y pintar el resultado.
   Ninguna operación criptográfica se implementa aquí: todas viven en cripto.js.
   ============================================================================ */

/* ---------------------------------------------------------------------------
   Criptogramas de la guía del taller (páginas 4 y 5 del documento).
--------------------------------------------------------------------------- */
const RETOS_GUIA = [
  {
    titulo: "Reto 1 — Cifrado César",
    nota: "La guía anuncia k = 11, pero el criptograma publicado corresponde a k = 5.",
    criptograma:
      "MFGPFXTGWJPFMNXYTWNFIJPFHWNUYTLWFKNFIJXIJPFFRYNLZJIFIQJRHNTRFRITVZJPFRJHJXNIFIIJ" +
      "THZPYFWQJRXFÑJXMFJCNXYNITXNJQUWJUFWFUWTYJLJWXJHWJYTXQNPNYFWJXDUTPNYNHTX"
  },
  {
    titulo: "Reto 2 — Cifrado Afín",
    nota: "La letra más frecuente del criptograma es la H y corresponde a la A, no a la E.",
    criptograma:
      "ASGITQHAIHRHITUTUVAFPAQEARQTHUXQBNBIHUIAZPHUQBNBIHAXIHHUBRIHUNHUQBNERAUAR" +
      "AITVTBNHAUGHWBIGAPNTZTARVBPBNGAPQTFPHVBUNBRBHIFHMAZTQBUQBRPAIHZTJHFHQTITV" +
      "HV"
  },
  {
    titulo: "Reto 3 — Cifrado de Vigenère",
    nota: "IC de 0.049: estadística aplanada. La longitud de clave se confirma por columnas.",
    criptograma:
      "PYTGECCIXUNEDOJQNYÑMSGBCOJNSNFBQGOSMZAMSSMPHQNDMRMBVXUFQÑFFXOBMILKBVW" +
      "WBPÑCBQPJFOOOSWBXFONNFKHHEESOFVEUNYZXJEXASEOCBWNFVWBXFONNQVUGFVNNDSYKV" +
      "XNXPVNNFOQWUVBGFGNHJGNN"
  }
];

/* ---------------------------------------------------------------------------
   Utilidades
--------------------------------------------------------------------------- */
const $ = (id) => document.getElementById(id);

/** Escapa el texto antes de meterlo en el HTML. */
function esc(texto) {
  return String(texto).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function mostrarError(elemento, mensaje) {
  elemento.textContent = mensaje;
  elemento.classList.remove("oculto");
}

function limpiarError(elemento) {
  elemento.textContent = "";
  elemento.classList.add("oculto");
}

/* ---------------------------------------------------------------------------
   1. ROMPER UN CRIPTOGRAMA
--------------------------------------------------------------------------- */
function analizarCriptograma() {
  const salida = $("resultado");
  limpiarError($("errorAnalisis"));

  const texto = $("criptograma").value;
  const opciones = {};
  if ($("metodo").value) opciones.metodo = $("metodo").value;
  if ($("longitudClave").value) opciones.longitudClave = Number($("longitudClave").value);

  try {
    const analisis = analizar(texto, opciones);   // definido en cripto.js
    salida.innerHTML = renderResultado(analisis);
    salida.querySelector("#btnCopiarClaro")
          .addEventListener("click", () => copiar(analisis.resultado.textoDescifrado));
    salida.classList.remove("oculto");
    salida.scrollIntoView({ block: "nearest" });
  } catch (e) {
    salida.classList.add("oculto");
    mostrarError($("errorAnalisis"), e.message);
  }
}

function renderResultado(a) {
  const r = a.resultado;
  const confianza = Math.round(a.diagnostico.confianza * 100);

  let html = `
    <div class="veredicto">
      <dl>
        <dt>Cifrado</dt><dd>${esc(r.metodo)}</dd>
        <dt>Clave</dt><dd class="clave">${esc(r.clave)}</dd>
        <dt>Ajuste al español</dt><dd>chi² = ${r.chi.toFixed(1)}</dd>
      </dl>
    </div>
    <div class="salida">${esc(r.textoDescifrado)}</div>
    <div class="acciones">
      <button class="secundario" id="btnCopiarClaro">Copiar texto descifrado</button>
    </div>`;

  if (a.longitud < 100) {
    html += `<p class="aviso">El criptograma tiene ${a.longitud} letras. Por debajo de
             unas 100, la estadística es inestable y el resultado puede ser incorrecto.</p>`;
  }
  if (a.metodoForzado) {
    html += `<p class="aviso">Ataque forzado manualmente. El diagnóstico automático decía
             ${esc(a.diagnostico.tipo)}.</p>`;
  }

  html += `
    <details open>
      <summary>Índice de coincidencia y diagnóstico</summary>
      <div class="cuerpo">
        <p>${esc(a.diagnostico.mensaje)}</p>
        <table>
          <tr><th>IC del criptograma</th><td class="num">${a.diagnostico.ic.toFixed(4)}</td></tr>
          <tr><th>IC de un texto en español</th><td class="num">${a.diagnostico.referencias.espanol.toFixed(4)}</td></tr>
          <tr><th>IC de un texto aleatorio (1/27)</th><td class="num">${a.diagnostico.referencias.aleatorio.toFixed(4)}</td></tr>
          <tr><th>Longitud analizada</th><td class="num">${a.longitud} letras</td></tr>
          <tr><th>Confianza del diagnóstico</th><td class="num">${confianza}%</td></tr>
        </table>
      </div>
    </details>

    <details>
      <summary>Conteo de frecuencias</summary>
      <div class="cuerpo">${renderFrecuencias(a)}</div>
    </details>`;

  for (const ataque of a.ataques) {
    html += `
      <details>
        <summary>Ataque: ${esc(ataque.metodo)} — ${esc(ataque.ataque)}</summary>
        <div class="cuerpo">${renderEvidencia(ataque)}</div>
      </details>`;
  }

  html += `
    <details>
      <summary>Texto normalizado que se analizó</summary>
      <div class="cuerpo"><div class="salida">${esc(a.textoNormalizado)}</div></div>
    </details>`;

  return html;
}

/** Barras de frecuencia observada, con una marca en la frecuencia del español. */
function renderFrecuencias(a) {
  const maximo = Math.max(...a.ordenadas.map((f) => f.porcentaje), 14);
  const filas = ALFABETO.split("").map((letra) => {
    const pct = a.frecuencias.porcentaje[letra];
    const esperado = FRECUENCIAS_ESPANOL[letra];
    return `
      <span class="letra">${letra}</span>
      <span class="barra">
        <i style="width:${(pct / maximo) * 100}%"></i>
        <span class="esperado" style="left:${(esperado / maximo) * 100}%"></span>
      </span>
      <span class="valor">${pct.toFixed(1)}%</span>`;
  }).join("");

  const top = a.ordenadas.slice(0, 5)
    .map((f) => `${f.letra} (${f.conteo})`).join(", ");

  return `
    <p>Letras más frecuentes del criptograma: ${esc(top)}.</p>
    <div class="frecuencias">${filas}</div>
    <p class="leyenda"><span class="marca"></span> frecuencia esperada de esa letra en español.</p>`;
}

/** Evidencia detrás de cada ataque. Cambia según el método. */
function renderEvidencia(ataque) {
  if (ataque.metodo === "César") {
    const filas = ataque.candidatos.slice(0, 6).map((c, i) => `
      <tr class="${i === 0 ? "destacada" : ""}">
        <td class="num">${c.clave}</td>
        <td class="num">${c.chi.toFixed(0)}</td>
        <td class="mono">${esc(c.descifrado.slice(0, 44))}…</td>
      </tr>`).join("");
    return `
      <p>Se descifró con los 27 desplazamientos y se ordenaron por chi². Los seis mejores:</p>
      <table>
        <tr><th class="num">k</th><th class="num">chi²</th><th>Inicio del texto</th></tr>
        ${filas}
      </table>`;
  }

  if (ataque.metodo === "Afín") {
    const ec = ataque.ecuaciones;
    const fb = ataque.fuerzaBruta;

    const filasEc = (ec.candidatos || []).slice(0, 5).map((c, i) => `
      <tr class="${i === 0 && ataque.ecuacionesAcerto ? "destacada" : ""}">
        <td>${esc(c.supuesto)}</td>
        <td class="mono">${esc(c.claveTexto)}</td>
        <td class="num">${c.chi.toFixed(0)}</td>
        <td class="mono">${esc(c.descifrado.slice(0, 30))}…</td>
      </tr>`).join("");

    const filasFb = fb.candidatos.slice(0, 3).map((c, i) => `
      <tr class="${i === 0 ? "destacada" : ""}">
        <td class="mono">${esc(c.claveTexto)}</td>
        <td class="num">${c.chi.toFixed(0)}</td>
        <td class="mono">${esc(c.descifrado.slice(0, 40))}…</td>
      </tr>`).join("");

    return `
      <p>
        Letras más frecuentes del criptograma: ${esc(ec.letrasMasFrecuentes.join(", "))}.
        Se plantearon ${ec.intentos} sistemas de ecuaciones suponiendo que esas letras
        corresponden a las más frecuentes del español (E, A, O, S).
      </p>
      <table>
        <tr><th>Suposición</th><th>Clave resultante</th><th class="num">chi²</th><th>Inicio del texto</th></tr>
        ${filasEc}
      </table>
      ${ataque.ecuacionesAcerto
        ? ""
        : `<p class="aviso">Ninguna hipótesis de frecuencias dio con la clave. Se tomó el
           resultado de la fuerza bruta.</p>`}
      <p style="margin-top:1.25rem">Comprobación por fuerza bruta sobre las ${fb.intentos} claves válidas:</p>
      <table>
        <tr><th>Clave</th><th class="num">chi²</th><th>Inicio del texto</th></tr>
        ${filasFb}
      </table>`;
  }

  // Vigenère
  const filasLong = ataque.longitudes.map((f) => `
    <tr class="${f.longitud === ataque.longitudUsada ? "destacada" : ""}">
      <td class="num">${f.longitud}</td>
      <td class="num">${f.ic.toFixed(4)}</td>
    </tr>`).join("");

  const filasCol = ataque.columnas.map((c) => `
    <tr>
      <td class="num">${c.indice + 1}</td>
      <td class="num">${c.longitud}</td>
      <td class="num">${c.ic.toFixed(4)}</td>
      <td class="mono">${c.letraClave} (${c.desplazamiento})</td>
      <td class="mono">${c.alternativas.slice(1).map((x) => x.letra).join(", ")}</td>
    </tr>`).join("");

  const repes = ataque.kasiski.repeticiones.slice(0, 6).map((r) => `
    <tr>
      <td class="mono">${esc(r.secuencia)}</td>
      <td class="num">${r.posiciones.join(", ")}</td>
      <td class="num">${r.distancias.join(", ")}</td>
    </tr>`).join("");

  const divisores = ataque.kasiski.divisores.slice(0, 6)
    .map((d) => `${d.longitud} (${d.votos} veces)`).join(", ");

  return `
    <p><strong>Paso 1 — Kasiski.</strong> Secuencias repetidas y distancias entre sus apariciones:</p>
    <table>
      <tr><th>Secuencia</th><th class="num">Posiciones</th><th class="num">Distancias</th></tr>
      ${repes || '<tr><td colspan="3">No se hallaron repeticiones útiles.</td></tr>'}
    </table>
    <p style="margin-top:.8rem">Divisores más votados por esas distancias: ${esc(divisores || "ninguno")}.</p>

    <p style="margin-top:1.25rem"><strong>Paso 2 — IC por columnas.</strong> Se elige la longitud
    más corta cuyo IC promedio ya alcanza el del español:</p>
    <table>
      <tr><th class="num">Longitud</th><th class="num">IC promedio</th></tr>
      ${filasLong}
    </table>

    <p style="margin-top:1.25rem"><strong>Paso 3 — Un César por columna.</strong></p>
    <table>
      <tr><th class="num">Columna</th><th class="num">Letras</th><th class="num">IC</th>
          <th>Letra de clave</th><th>Alternativas</th></tr>
      ${filasCol}
    </table>`;
}

/* ---------------------------------------------------------------------------
   2. CIFRAR
--------------------------------------------------------------------------- */
function ajustarCamposCifrado() {
  const metodo = $("metodoCifrado").value;
  document.querySelectorAll(".campo-cesar").forEach((e) => e.classList.toggle("oculto", metodo !== "cesar"));
  document.querySelectorAll(".campo-afin").forEach((e) => e.classList.toggle("oculto", metodo !== "afin"));
  document.querySelectorAll(".campo-vigenere").forEach((e) => e.classList.toggle("oculto", metodo !== "vigenere"));
}

function cifrarTexto() {
  limpiarError($("errorCifrado"));
  const texto = $("textoClaro").value;
  const metodo = $("metodoCifrado").value;

  try {
    if (!normalizar(texto)) throw new Error("Escribe un texto con al menos una letra.");

    let cifrado;
    if (metodo === "cesar") cifrado = cesarCifrar(texto, Number($("claveK").value));
    else if (metodo === "afin") cifrado = afinCifrar(texto, Number($("claveA").value), Number($("claveB").value));
    else cifrado = vigenereCifrar(texto, $("clavePalabra").value);

    $("textoCifrado").textContent = cifrado;
    $("salidaCifrado").classList.remove("oculto");
  } catch (e) {
    $("salidaCifrado").classList.add("oculto");
    mostrarError($("errorCifrado"), e.message);
  }
}

function copiar(texto) {
  navigator.clipboard.writeText(texto);
}

/* ---------------------------------------------------------------------------
   3. RETOS DE LA GUÍA
--------------------------------------------------------------------------- */
function pintarRetos() {
  $("listaRetos").innerHTML = RETOS_GUIA.map((reto, i) => `
    <div class="reto">
      <h3>${esc(reto.titulo)}</h3>
      <p>${esc(reto.nota)}</p>
      <button class="secundario" data-reto="${i}">Cargar y analizar</button>
    </div>`).join("");

  $("listaRetos").querySelectorAll("button[data-reto]").forEach((boton) => {
    boton.addEventListener("click", () => {
      $("criptograma").value = RETOS_GUIA[boton.dataset.reto].criptograma;
      $("metodo").value = "";
      $("longitudClave").value = "";
      analizarCriptograma();
      $("seccion-romper").scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
}

/* ---------------------------------------------------------------------------
   Barra de sesión
   Solo decide qué enlaces mostrar. No protege nada: la herramienta de
   criptoanálisis es pública a propósito, y lo que sí está restringido (el
   panel) lo comprueba el servidor en cada petición.
--------------------------------------------------------------------------- */
async function pintarBarraSesion() {
  const barra = $("barraSesion");
  if (!barra) return;
  try {
    const respuesta = await fetch("/sesion");
    if (respuesta.ok) {
      const { usuario } = await respuesta.json();
      barra.innerHTML = `${usuario.username} (${usuario.rol}) · ` +
        `<a href="/panel.html">Panel</a> · <a href="#" id="salir">Cerrar sesión</a>`;
      document.getElementById("salir").addEventListener("click", async (e) => {
        e.preventDefault();
        await fetch("/logout", { method: "POST" });
        location.reload();
      });
    } else {
      barra.innerHTML = `<a href="/login.html">Iniciar sesión</a> · <a href="/registro.html">Crear cuenta</a>`;
    }
  } catch (e) {
    barra.textContent = "";
  }
}

/* ---------------------------------------------------------------------------
   Arranque
--------------------------------------------------------------------------- */
$("btnAnalizar").addEventListener("click", analizarCriptograma);
$("btnLimpiar").addEventListener("click", () => {
  $("criptograma").value = "";
  $("resultado").classList.add("oculto");
  limpiarError($("errorAnalisis"));
});
$("btnCifrar").addEventListener("click", cifrarTexto);
$("metodoCifrado").addEventListener("change", ajustarCamposCifrado);
$("btnCopiarCifrado").addEventListener("click", () => copiar($("textoCifrado").textContent));
$("btnRomperEste").addEventListener("click", () => {
  $("criptograma").value = $("textoCifrado").textContent;
  analizarCriptograma();
  $("seccion-romper").scrollIntoView({ behavior: "smooth", block: "start" });
});

ajustarCamposCifrado();
pintarRetos();
pintarBarraSesion();
