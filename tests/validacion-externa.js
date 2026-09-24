// Mide las heurísticas contra listas que NO he escrito yo. Las otras suites prueban ataques
// inventados por quien también escribió las defensas, así que confirman lo que ya se esperaba;
// esto da la cifra que de verdad se puede publicar.
import { checkUrl } from "../public/js/modules/urlModule.js";

const estado = document.getElementById("estado");
const resumen = document.getElementById("resumen");
const detalle = document.getElementById("detalle");

const LIMITE = Number(new URLSearchParams(location.search).get("n") || 5000);

async function cargar(nombre) {
  const res = await fetch(`_corpus/${nombre}.json`);
  if (!res.ok) throw new Error(`falta tests/_corpus/${nombre}.json — ver README`);
  return res.json();
}

// Se cede el hilo cada pocas entradas para que la página siga respondiendo y se vea el avance.
async function recorrer(entradas, aUrl, etiqueta) {
  const conteo = { total: 0, marcadas: 0, peligrosas: 0, errores: 0 };
  const porFlag = new Map();
  const ejemplos = [];
  for (let i = 0; i < entradas.length; i++) {
    if (i % 250 === 0) {
      estado.textContent = `${etiqueta}: ${i} de ${entradas.length}…`;
      await new Promise((r) => setTimeout(r, 0));
    }
    try {
      const r = await checkUrl(aUrl(entradas[i]), { networkEnabled: false, persist: false });
      conteo.total++;
      if (r.verdict !== "safe") {
        conteo.marcadas++;
        if (r.verdict === "dangerous") conteo.peligrosas++;
        for (const f of r.flags) porFlag.set(f, (porFlag.get(f) || 0) + 1);
        if (ejemplos.length < 25) ejemplos.push({ entrada: entradas[i], v: r.verdict, s: r.riskScore, flags: r.flags.join(", ") });
      }
    } catch {
      conteo.errores++;
    }
  }
  return { conteo, porFlag, ejemplos };
}

function tarjeta(titulo, cifra, pie, clase = "") {
  return `<div class="tarjeta"><div class="hint">${titulo}</div>
    <div class="cifra ${clase}">${cifra}</div><div class="hint">${pie}</div></div>`;
}

function tabla(titulo, filas, cabeceras) {
  if (!filas.length) return "";
  return `<h2>${titulo}</h2><table><tr>${cabeceras.map((c) => `<th>${c}</th>`).join("")}</tr>` +
    filas.map((f) => `<tr>${f.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") + `</table>`;
}

const esc = (t) => { const d = document.createElement("div"); d.textContent = t; return d.innerHTML; };

(async () => {
  try {
    const [legitimos, phishing] = await Promise.all([cargar("legitimos"), cargar("phishing")]);
    const l = legitimos.slice(0, LIMITE);
    const p = phishing.slice(0, LIMITE);

    const t0 = performance.now();
    const rl = await recorrer(l, (d) => `https://${d}/`, "Dominios legítimos (Tranco)");
    const rp = await recorrer(p, (u) => u, "Phishing confirmado");
    const segundos = ((performance.now() - t0) / 1000).toFixed(0);

    const fp = (100 * rl.conteo.marcadas) / rl.conteo.total;
    const det = (100 * rp.conteo.marcadas) / rp.conteo.total;
    estado.textContent = `${rl.conteo.total} dominios legítimos y ${rp.conteo.total} URLs de phishing en ${segundos}s. Red apagada.`;

    resumen.innerHTML =
      tarjeta("Falsos positivos<br>(Tranco, legítimos)", `${fp.toFixed(2)}%`, `${rl.conteo.marcadas} de ${rl.conteo.total} marcados`) +
      tarjeta("Detección<br>(phishing confirmado)", `${det.toFixed(1)}%`, `${rp.conteo.marcadas} de ${rp.conteo.total} detectadas`) +
      tarjeta("De esas, como peligrosas", `${((100 * rp.conteo.peligrosas) / rp.conteo.total).toFixed(1)}%`, `${rp.conteo.peligrosas} con veredicto "dangerous"`) +
      tarjeta("No analizables", `${rl.conteo.errores + rp.conteo.errores}`, "URL malformada o no parseable");

    const ordenadas = (m, tot) => [...m.entries()].sort((a, b) => b[1] - a[1])
      .map(([f, n]) => [esc(f), n, `${((100 * n) / tot).toFixed(2)}%`]);

    detalle.innerHTML =
      tabla("Qué heurística marca a los legítimos (causa de los falsos positivos)",
        ordenadas(rl.porFlag, rl.conteo.total), ["Señal", "Veces", "% del corpus legítimo"]) +
      tabla("Qué heurística detecta el phishing",
        ordenadas(rp.porFlag, rp.conteo.total), ["Señal", "Veces", "% del corpus de phishing"]) +
      tabla("Legítimos marcados (muestra para revisar a mano)",
        rl.ejemplos.map((e) => [esc(e.entrada), e.v, e.s, esc(e.flags)]), ["Dominio", "Veredicto", "Riesgo", "Señales"]);
  } catch (e) {
    estado.innerHTML = `<strong>No se pudo ejecutar:</strong> ${esc(e.message)}`;
  }
})();
