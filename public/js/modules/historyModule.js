import { listResults, deleteResult, clearAll } from "../db.js";
import { FLAG_LABELS } from "./urlModule.js";
import { FILE_FLAG_LABELS } from "./fileModule.js";
import { MAIL_FLAG_LABELS } from "./mailModule.js";
import { SMS_FLAG_LABELS } from "./smsModule.js";
import { DNS_FLAG_LABELS } from "./dnsModule.js";

const ALL_LABELS = { ...FLAG_LABELS, ...FILE_FLAG_LABELS, ...MAIL_FLAG_LABELS, ...SMS_FLAG_LABELS, ...DNS_FLAG_LABELS };

function fmtTime(ts) {
  return new Date(ts).toLocaleString();
}

// Mismo conjunto de iconos que el resto de la app (sprite SVG de index.html): los emojis que
// había aquí los dibuja cada sistema a su manera y desentonaban con las tarjetas.
const TYPE_ICONS = {
  url: "i-url", file: "i-file", mail: "i-mail", sms: "i-sms",
  app: "i-apps", apps: "i-apps", dns: "i-dns", qr: "i-qr",
};
function typeIcon(type) {
  const id = TYPE_ICONS[type];
  if (!id) return "";
  return `<svg class="h-icon" viewBox="0 0 24 24" aria-hidden="true"><use href="#${id}"/></svg>`;
}

// El veredicto se guardaba en inglés porque es la clave interna; en pantalla no pinta nada.
const VERDICT_LABELS = {
  dangerous: "peligroso",
  suspicious: "sospechoso",
  safe: "sin señales",
  unknown: "sin datos",
};

export async function renderHistory(listEl) {
  const items = await listResults();
  listEl.innerHTML = "";

  if (items.length === 0) {
    listEl.innerHTML = '<p class="empty">Sin resultados guardados todavía.</p>';
    return;
  }

  for (const item of items) {
    const el = document.createElement("div");
    el.className = "history-item";
    el.innerHTML = `
      <div class="h-top">
        <div>
          <span class="verdict ${item.verdict}">${VERDICT_LABELS[item.verdict] || item.verdict}</span>
        </div>
        <button class="h-del" title="Borrar" aria-label="Borrar">✕</button>
      </div>
      <div class="h-input">${typeIcon(item.type)}<span>${escapeHtml(item.input)}</span></div>
      <div class="h-time">${fmtTime(item.timestamp)}</div>
      <div class="h-detail" hidden></div>
    `;

    el.querySelector(".h-del").addEventListener("click", async (e) => {
      e.stopPropagation();
      await deleteResult(item.id);
      renderHistory(listEl);
    });

    el.addEventListener("click", () => {
      const detail = el.querySelector(".h-detail");
      if (detail.hidden) {
        detail.hidden = false;
        detail.innerHTML = renderDetail(item);
      } else {
        detail.hidden = true;
      }
    });

    listEl.appendChild(el);
  }
}

function renderDetail(item) {
  // Escapado obligatorio: hoy solo llegan claves internas, pero este es un sink de HTML y
  // basta con que un módulo futuro guarde un flag con datos del archivo analizado para
  // convertirlo en XSS almacenado (el historial persiste en IndexedDB y se re-renderiza).
  const flags = (item.flags || [])
    .map((f) => `<li class="warn">${escapeHtml(ALL_LABELS[f] || f)}</li>`)
    .join("");
  const extra = item.raw?.finalUrl
    ? `<div class="chain">${escapeHtml(item.raw.input)}<span class="arrow">→</span>${escapeHtml(item.raw.finalUrl)}</div>`
    : "";
  return `
    ${extra}
    <div class="score">Riesgo: ${item.riskScore ?? "—"}</div>
    <ul class="flags">${flags || "<li class=\"info\">Sin señales de riesgo</li>"}</ul>
  `;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

export async function wireHistoryTab(listEl, clearBtn) {
  await renderHistory(listEl);
  clearBtn.addEventListener("click", async () => {
    if (!confirm("¿Borrar todo el historial?")) return;
    await clearAll();
    renderHistory(listEl);
  });
}
