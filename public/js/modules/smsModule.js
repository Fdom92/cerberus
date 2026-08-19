import { saveResult } from "../db.js";
import { offlineUrlFlags, FLAG_LABELS as URL_FLAG_LABELS, FLAG_POINTS as URL_FLAG_POINTS } from "./urlModule.js";

const URGENCY_WORDS = [
  "urgente", "urgent", "inmediat", "immediat", "suspendid", "suspended",
  "bloquead", "blocked", "últimas horas", "last hours", "24 horas", "24 hours",
  "expira", "expires", "caduca", "act now", "actúa ya", "limited time",
  "tiempo limitado",
];

const CREDENTIAL_WORDS = [
  "verifica tu cuenta", "verify your account", "actualiza tus datos", "update your details",
  "confirma tu identidad", "confirm your identity", "código de verificación", "verification code",
  "contraseña", "password", "pin de seguridad", "security pin", "introduce tu", "enter your",
];

const LURE_WORDS = [
  "has ganado", "you won", "premio", "prize", "reembolso", "refund",
  "paquete retenido", "package held", "aduana", "customs", "factura pendiente", "pending invoice",
  "impago", "unpaid",
];

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly"];

const FLAG_POINTS = {
  credential_request: 30,
  lure_language: 20,
  urgency_language: 15,
  shortened_url: 15,
  multiple_urls: 10,
  ...URL_FLAG_POINTS,
};

export const SMS_FLAG_LABELS = {
  credential_request: "Pide verificar cuenta, contraseña o código — patrón clásico de phishing",
  lure_language: "Usa gancho de premio, reembolso o paquete retenido para generar clic",
  urgency_language: "Lenguaje de urgencia/presión temporal — táctica común de smishing",
  shortened_url: "Contiene un enlace acortado — oculta el destino real",
  multiple_urls: "Contiene más de un enlace",
  ...URL_FLAG_LABELS,
};

function extractUrls(text) {
  const matches = text.match(/\bhttps?:\/\/[^\s<>"')]+/gi) || [];
  const bare = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')]*)?/gi) || [];
  const all = [...matches];
  for (const b of bare) {
    if (!matches.some((m) => m.includes(b))) all.push(b);
  }
  return [...new Set(all)];
}

function matchesAny(text, words) {
  const lower = text.toLowerCase();
  return words.some((w) => lower.includes(w));
}

export async function checkSms(rawText) {
  const flags = [];
  const urls = extractUrls(rawText);

  if (matchesAny(rawText, CREDENTIAL_WORDS)) flags.push("credential_request");
  if (matchesAny(rawText, LURE_WORDS)) flags.push("lure_language");
  if (matchesAny(rawText, URGENCY_WORDS)) flags.push("urgency_language");
  if (urls.length > 1) flags.push("multiple_urls");

  const urlDetails = [];
  for (const raw of urls) {
    const { href, flags: uFlags } = await offlineUrlFlags(raw);
    urlDetails.push({ raw, href, flags: uFlags });
    for (const f of uFlags) if (!flags.includes(f)) flags.push(f);
    try {
      const host = new URL(href).hostname.replace(/^www\./, "");
      if (SHORTENERS.includes(host) && !flags.includes("shortened_url")) flags.push("shortened_url");
    } catch {
      /* ignore */
    }
  }

  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";

  const result = {
    type: "sms",
    text: rawText,
    urls: urlDetails,
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "sms",
    input: rawText.length > 80 ? rawText.slice(0, 80) + "…" : rawText,
    verdict,
    riskScore,
    flags,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}
