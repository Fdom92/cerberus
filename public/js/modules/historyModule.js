import { listResults, deleteResult, clearAll } from "../db.js";
import { FLAG_LABELS } from "./urlModule.js";
import { FILE_FLAG_LABELS } from "./fileModule.js";
import { MAIL_FLAG_LABELS } from "./mailModule.js";
import { SMS_FLAG_LABELS } from "./smsModule.js";

const ALL_LABELS = { ...FLAG_LABELS, ...FILE_FLAG_LABELS, ...MAIL_FLAG_LABELS, ...SMS_FLAG_LABELS };

function fmtTime(ts) {
  return new Date(ts).toLocaleString();
}

const TYPE_ICONS = { url: "🔗", file: "📄", mail: "✉️", sms: "💬" };
function typeIcon(type) {
  return TYPE_ICONS[type] || "•";
}

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
          <span class="verdict ${item.verdict}">${item.verdict}</span>
        </div>
        <button class="h-del" title="Borrar" aria-label="Borrar">✕</button>
      </div>
      <div class="h-input">${typeIcon(item.type)} ${escapeHtml(item.input)}</div>
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
  const flags = (item.flags || [])
    .map((f) => `<li class="warn">${ALL_LABELS[f] || f}</li>`)
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
