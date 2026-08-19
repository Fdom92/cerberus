import { checkUrl, FLAG_LABELS } from "./modules/urlModule.js";
import { checkFile, FILE_FLAG_LABELS } from "./modules/fileModule.js";
import { checkMail, MAIL_FLAG_LABELS } from "./modules/mailModule.js";
import { checkSms, SMS_FLAG_LABELS } from "./modules/smsModule.js";
import { decodeJwt, JWT_FLAG_LABELS } from "./modules/jwtModule.js";
import { estimatePassword, PASSWORD_FLAG_LABELS } from "./modules/passwordModule.js";
import { decodeAll } from "./modules/decodeModule.js";
import { parseExif } from "./modules/exifModule.js";
import { scanSecrets } from "./modules/secretsModule.js";
import { checkApp } from "./modules/appsModule.js";
import { wireHistoryTab } from "./modules/historyModule.js";
import {
  SAMPLES,
  sampleSafePdfFile,
  sampleDisguisedFile,
  sampleGpsPhotoFile,
  sampleCleanPhotoFile,
  sampleSpywareApkFile,
  sampleSpywareIpaFile,
} from "./sampleData.js";

const ALL_FLAG_LABELS = {
  ...FLAG_LABELS,
  ...FILE_FLAG_LABELS,
  ...MAIL_FLAG_LABELS,
  ...SMS_FLAG_LABELS,
  ...JWT_FLAG_LABELS,
  ...PASSWORD_FLAG_LABELS,
};
const NET_PREF_KEY = "cerberus_net_enabled";

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function flagsHtml(flags, emptyText = "Sin señales de riesgo") {
  if (!flags || flags.length === 0) return `<li class="info">${escapeHtml(emptyText)}</li>`;
  return flags.map((f) => `<li class="warn">${escapeHtml(ALL_FLAG_LABELS[f] || f)}</li>`).join("");
}

function wireSample(buttonId, inputEl, value, formEl) {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  btn.addEventListener("click", () => {
    inputEl.value = value;
    if (formEl) formEl.requestSubmit();
    else inputEl.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

// ---- Navigation (home grid + per-tool panels) ----
function showPanel(id) {
  document.querySelectorAll("main > .panel").forEach((p) => p.classList.remove("active"));
  document.getElementById(`panel-${id}`).classList.add("active");
  if (id === "history") historyRefresh();
}

function goHome() {
  showPanel("home");
}

function initNav() {
  document.querySelectorAll(".tool-card[data-open]").forEach((card) => {
    card.addEventListener("click", () => showPanel(card.dataset.open));
  });
  document.querySelectorAll("[data-back]").forEach((btn) => btn.addEventListener("click", goHome));
  document.getElementById("historyBtn").addEventListener("click", () => showPanel("history"));
  const brand = document.getElementById("brandHome");
  brand.addEventListener("click", goHome);
  brand.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      goHome();
    }
  });
}

// ---- Network toggle ----
function initNetToggle() {
  const toggle = document.getElementById("netToggle");
  const warn = document.getElementById("netWarn");
  const badge = document.getElementById("netBadge");
  const netState = document.getElementById("netState");

  const saved = localStorage.getItem(NET_PREF_KEY) === "1";
  toggle.checked = saved;
  updateNetUi(saved);

  toggle.addEventListener("change", () => {
    localStorage.setItem(NET_PREF_KEY, toggle.checked ? "1" : "0");
    updateNetUi(toggle.checked);
  });

  function updateNetUi(enabled) {
    warn.hidden = !enabled;
    badge.textContent = enabled ? "red activa" : "local";
    badge.classList.toggle("online", enabled);
    netState.textContent = enabled ? "red activada" : "red desactivada";
  }
}

function isNetEnabled() {
  return localStorage.getItem(NET_PREF_KEY) === "1";
}

// ---- URL module ----
function initUrlForm() {
  const form = document.getElementById("urlForm");
  const input = document.getElementById("urlInput");
  const resultEl = document.getElementById("urlResult");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = input.value.trim();
    if (!raw) return;

    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Analizando…</p>';

    try {
      const result = await checkUrl(raw, { networkEnabled: isNetEnabled() });
      renderUrlResult(resultEl, result);
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo analizar: ${escapeHtml(err.message || String(err))}</p>`;
    }
  });

  wireSample("sampleUrlSafe", input, SAMPLES.urlSafe, form);
  wireSample("sampleUrlMalicious", input, SAMPLES.urlMalicious, form);
}

function renderUrlResult(el, r) {
  const chain = r.finalUrl
    ? `<div class="chain">${escapeHtml(r.input)}<span class="arrow">→</span>${escapeHtml(r.finalUrl)}</div>`
    : "";
  const meta = [];
  if (r.httpCode !== null && r.httpCode !== undefined) meta.push(`HTTP ${r.httpCode}`);
  if (r.ageDays !== null && r.ageDays !== undefined) meta.push(`dominio con ${r.ageDays} días`);

  el.innerHTML = `
    <span class="verdict ${r.verdict}">${r.verdict}</span>
    <div class="score">Riesgo: ${r.riskScore} / 100</div>
    ${chain}
    <ul class="flags">${flagsHtml(r.flags)}</ul>
    ${meta.length ? `<div class="meta">${meta.map(escapeHtml).join(" · ")}</div>` : ""}
  `;
}

// ---- File module ----
function initFileModule() {
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const resultEl = document.getElementById("fileResult");

  const handle = async (file) => {
    if (!file) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Leyendo archivo…</p>';
    try {
      const result = await checkFile(file);
      renderFileResult(resultEl, result);
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo leer: ${escapeHtml(err.message || String(err))}</p>`;
    }
  };

  fileInput.addEventListener("change", () => handle(fileInput.files[0]));
  wireDropZone(dropZone, handle);

  document.getElementById("sampleFileSafe").addEventListener("click", () => handle(sampleSafePdfFile()));
  document.getElementById("sampleFileMalicious").addEventListener("click", () => handle(sampleDisguisedFile()));
}

function wireDropZone(dropZone, handle) {
  ["dragenter", "dragover"].forEach((evt) =>
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragover");
    })
  );
  dropZone.addEventListener("drop", (e) => handle(e.dataTransfer.files?.[0]));
}

function renderFileResult(el, r) {
  const hashLine = r.sha256
    ? `<div class="meta mono">SHA-256: ${escapeHtml(r.sha256)}</div>`
    : `<div class="meta">SHA-256: omitido (archivo &gt;50MB)</div>`;
  el.innerHTML = `
    <span class="verdict ${r.verdict}">${r.verdict}</span>
    <div class="score">${escapeHtml(r.input)} — ${(r.size / 1024).toFixed(1)} KB</div>
    <div class="meta">Extensión declarada: .${escapeHtml(r.declaredExt)} · Tipo detectado: ${escapeHtml(r.detected)}</div>
    <div class="meta">Entropía: ${r.entropy} / 8 bits/byte</div>
    ${hashLine}
    <ul class="flags">${flagsHtml(r.flags)}</ul>
  `;
}

// ---- Mail module ----
function initMailForm() {
  const form = document.getElementById("mailForm");
  const input = document.getElementById("mailInput");
  const resultEl = document.getElementById("mailResult");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = input.value.trim();
    if (!raw) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Analizando cabeceras…</p>';
    try {
      const r = await checkMail(raw);
      const meta = [];
      if (r.fromDomain) meta.push(`From: ${r.fromDomain}`);
      if (r.returnPathDomain) meta.push(`Return-Path: ${r.returnPathDomain}`);
      if (r.replyToDomain) meta.push(`Reply-To: ${r.replyToDomain}`);
      resultEl.innerHTML = `
        <span class="verdict ${r.verdict}">${r.verdict}</span>
        <div class="score">Riesgo: ${r.riskScore} / 100</div>
        <ul class="flags">${flagsHtml(r.flags)}</ul>
        ${meta.length ? `<div class="meta">${meta.map(escapeHtml).join(" · ")}</div>` : ""}
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo analizar: ${escapeHtml(err.message || String(err))}</p>`;
    }
  });

  wireSample("sampleMailSafe", input, SAMPLES.mailSafe, form);
  wireSample("sampleMailMalicious", input, SAMPLES.mailMalicious, form);
}

// ---- SMS module ----
function initSmsForm() {
  const form = document.getElementById("smsForm");
  const input = document.getElementById("smsInput");
  const resultEl = document.getElementById("smsResult");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const raw = input.value.trim();
    if (!raw) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Analizando…</p>';
    try {
      const r = await checkSms(raw);
      const urlsHtml = r.urls.length
        ? `<div class="meta">Enlaces detectados: ${r.urls.map((u) => escapeHtml(u.href)).join(", ")}</div>`
        : "";
      resultEl.innerHTML = `
        <span class="verdict ${r.verdict}">${r.verdict}</span>
        <div class="score">Riesgo: ${r.riskScore} / 100</div>
        <ul class="flags">${flagsHtml(r.flags)}</ul>
        ${urlsHtml}
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo analizar: ${escapeHtml(err.message || String(err))}</p>`;
    }
  });

  wireSample("sampleSmsSafe", input, SAMPLES.smsSafe, form);
  wireSample("sampleSmsMalicious", input, SAMPLES.smsMalicious, form);
}

// ---- JWT tool ----
function initJwtTool() {
  const form = document.getElementById("jwtForm");
  const input = document.getElementById("jwtInput");
  const resultEl = document.getElementById("jwtResult");

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const raw = input.value.trim();
    if (!raw) return;
    resultEl.hidden = false;
    try {
      const { header, payload, hasSignature, flags } = decodeJwt(raw);
      resultEl.innerHTML = `
        <ul class="flags">${flagsHtml(flags, "Sin señales llamativas en header/payload")}</ul>
        <div class="meta">${hasSignature ? "Tiene firma (no verificada aquí)" : "Sin firma"}</div>
        <div class="meta mono" style="white-space:pre-wrap;margin-top:8px">Header:\n${escapeHtml(JSON.stringify(header, null, 2))}</div>
        <div class="meta mono" style="white-space:pre-wrap;margin-top:8px">Payload:\n${escapeHtml(JSON.stringify(payload, null, 2))}</div>
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">${escapeHtml(err.message || String(err))}</p>`;
    }
  });

  wireSample("sampleJwtSafe", input, SAMPLES.jwtSafe, form);
  wireSample("sampleJwtMalicious", input, SAMPLES.jwtMalicious, form);
}

// ---- Password tool ----
function initPasswordTool() {
  const input = document.getElementById("passwordInput");
  const toggle = document.getElementById("passwordToggle");
  const resultEl = document.getElementById("passwordResult");

  toggle.addEventListener("click", () => {
    input.type = input.type === "password" ? "text" : "password";
    toggle.textContent = input.type === "password" ? "Ver" : "Ocultar";
  });

  input.addEventListener("input", () => {
    if (!input.value) {
      resultEl.hidden = true;
      return;
    }
    resultEl.hidden = false;
    const { entropy, category, flags, length } = estimatePassword(input.value);
    const pct = Math.min(100, Math.round((entropy / 80) * 100));
    const verdictClass = entropy < 28 ? "dangerous" : entropy < 60 ? "suspicious" : "safe";
    resultEl.innerHTML = `
      <span class="verdict ${verdictClass}">${escapeHtml(category)}</span>
      <div class="score">Entropía estimada: ${entropy} bits · ${length} caracteres</div>
      <div class="meta" style="background:var(--bg);border-radius:8px;height:8px;overflow:hidden;margin:6px 0 12px">
        <div style="width:${pct}%;height:100%;background:var(--accent)"></div>
      </div>
      <ul class="flags">${flagsHtml(flags, "Sin patrones débiles detectados")}</ul>
    `;
  });

  wireSample("samplePasswordWeak", input, SAMPLES.passwordWeak);
  wireSample("samplePasswordStrong", input, SAMPLES.passwordStrong);
}

// ---- Decode tool ----
function initDecodeTool() {
  const form = document.getElementById("decodeForm");
  const input = document.getElementById("decodeInput");
  const resultEl = document.getElementById("decodeResult");

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const raw = input.value;
    if (!raw.trim()) return;
    resultEl.hidden = false;
    const results = decodeAll(raw);
    if (results.length === 0) {
      resultEl.innerHTML = `<p class="hint">No se encontró ninguna decodificación válida (¿ya está en texto plano?).</p>`;
      return;
    }
    resultEl.innerHTML = results
      .map(
        (r) => `
        <div class="meta" style="margin-bottom:4px">${escapeHtml(r.label)}:</div>
        <div class="chain">${escapeHtml(r.value)}</div>
      `
      )
      .join("");
  });

  wireSample("sampleDecode", input, SAMPLES.decodeSample, form);
}

// ---- Secrets tool ----
function initSecretsTool() {
  const form = document.getElementById("secretsForm");
  const input = document.getElementById("secretsInput");
  const resultEl = document.getElementById("secretsResult");

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const raw = input.value;
    if (!raw.trim()) return;
    resultEl.hidden = false;
    const { findings, verdict, riskScore } = scanSecrets(raw);

    if (findings.length === 0) {
      resultEl.innerHTML = `
        <span class="verdict safe">safe</span>
        <ul class="flags"><li class="info">No se detectaron patrones de secretos conocidos</li></ul>
      `;
      return;
    }

    const items = findings
      .map((f) => {
        const cls = f.severity === "high" ? "bad" : "warn";
        const previews = f.previews.map(escapeHtml).join(", ");
        const more = f.count > f.previews.length ? ` (+${f.count - f.previews.length} más)` : "";
        return `<li class="${cls}"><strong>${escapeHtml(f.name)}</strong> — ${previews}${more}</li>`;
      })
      .join("");

    resultEl.innerHTML = `
      <span class="verdict ${verdict}">${verdict}</span>
      <div class="score">Riesgo: ${riskScore} / 100</div>
      <ul class="flags">${items}</ul>
    `;
  });

  wireSample("sampleSecretsSafe", input, SAMPLES.secretsClean, form);
  wireSample("sampleSecretsMalicious", input, SAMPLES.secretsDirty, form);
}

// ---- EXIF tool ----
function initExifTool() {
  const dropZone = document.getElementById("exifDropZone");
  const fileInput = document.getElementById("exifInput");
  const resultEl = document.getElementById("exifResult");

  const handle = async (file) => {
    if (!file) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Leyendo imagen…</p>';
    try {
      const buf = await file.arrayBuffer();
      const exif = parseExif(buf);
      if (!exif.hasExif) {
        resultEl.innerHTML = `<p class="hint">Sin datos EXIF (o no es JPEG con metadatos) — no se detectaron cámara, fecha ni GPS.</p>`;
        return;
      }
      const gpsHtml = exif.gps
        ? `<ul class="flags"><li class="bad">Coordenadas GPS: ${exif.gps.lat.toFixed(6)}, ${exif.gps.lon.toFixed(6)} — esta foto revela dónde se tomó</li></ul>`
        : `<ul class="flags"><li class="info">Sin coordenadas GPS</li></ul>`;
      const meta = [];
      if (exif.make || exif.model) meta.push(`Cámara: ${[exif.make, exif.model].filter(Boolean).join(" ")}`);
      if (exif.dateTimeOriginal || exif.dateTime) meta.push(`Fecha: ${exif.dateTimeOriginal || exif.dateTime}`);
      resultEl.innerHTML = `
        ${gpsHtml}
        ${meta.length ? `<div class="meta">${meta.map(escapeHtml).join(" · ")}</div>` : '<div class="meta">Sin más metadatos legibles</div>'}
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo leer EXIF: ${escapeHtml(err.message || String(err))}</p>`;
    }
  };

  fileInput.addEventListener("change", () => handle(fileInput.files[0]));
  wireDropZone(dropZone, handle);

  document.getElementById("sampleExifClean").addEventListener("click", () => handle(sampleCleanPhotoFile()));
  document.getElementById("sampleExifGps").addEventListener("click", () => handle(sampleGpsPhotoFile()));
}

// ---- Apps tool ----
function initAppsTool() {
  const dropZone = document.getElementById("appsDropZone");
  const fileInput = document.getElementById("appsInput");
  const resultEl = document.getElementById("appsResult");

  const handle = async (file) => {
    if (!file) return;
    resultEl.hidden = false;
    resultEl.innerHTML = '<p class="hint">Analizando…</p>';
    try {
      const r = await checkApp(file);
      const meta = [];
      if (r.package) meta.push(`Paquete: ${r.package}`);
      meta.push(`${(r.size / 1024).toFixed(1)} KB`);
      if (r.platform === "android") meta.push(`APK · ${r.permissions.length} permisos declarados`);
      else if (r.platform === "ios") meta.push(`IPA · ${r.permissions.length} permisos declarados`);
      else if (r.isZip) meta.push("ZIP sin manifest reconocido (no es APK ni IPA)");
      else meta.push("Binario (no ZIP)");

      const permItems = r.dangerousPermissions.map(
        (p) => `<li class="${p.severity === "high" ? "bad" : "warn"}">${escapeHtml(p.name)}</li>`
      );
      const secretItems = r.secretFindings.map(
        (f) => `<li class="bad"><strong>${escapeHtml(f.name)}</strong> — ${f.previews.map(escapeHtml).join(", ")}</li>`
      );
      const items = [...permItems, ...secretItems];

      resultEl.innerHTML = `
        <span class="verdict ${r.verdict}">${r.verdict}</span>
        <div class="score">Riesgo: ${r.riskScore} / 100</div>
        <div class="meta">${meta.map(escapeHtml).join(" · ")}</div>
        <ul class="flags">${items.length ? items.join("") : '<li class="info">Sin permisos peligrosos ni secretos detectados</li>'}</ul>
      `;
    } catch (err) {
      resultEl.innerHTML = `<p class="hint">No se pudo analizar: ${escapeHtml(err.message || String(err))}</p>`;
    }
  };

  fileInput.addEventListener("change", () => handle(fileInput.files[0]));
  wireDropZone(dropZone, handle);

  document.getElementById("sampleAppsApk").addEventListener("click", () => handle(sampleSpywareApkFile()));
  document.getElementById("sampleAppsIpa").addEventListener("click", () => handle(sampleSpywareIpaFile()));
}

// ---- History ----
let historyWired = false;
async function historyRefresh() {
  const listEl = document.getElementById("historyList");
  const clearBtn = document.getElementById("clearHistoryBtn");
  if (!historyWired) {
    historyWired = true;
    await wireHistoryTab(listEl, clearBtn);
  } else {
    const { renderHistory } = await import("./modules/historyModule.js");
    await renderHistory(listEl);
  }
}

// ---- Service worker ----
function registerSw() {
  if (!("serviceWorker" in navigator)) return;
  if (location.protocol === "file:") return; // SW requires http(s)
  navigator.serviceWorker.register("sw.js").catch(() => {});
}

initNav();
initNetToggle();
initUrlForm();
initFileModule();
initMailForm();
initSmsForm();
initJwtTool();
initPasswordTool();
initDecodeTool();
initSecretsTool();
initExifTool();
initAppsTool();
registerSw();
