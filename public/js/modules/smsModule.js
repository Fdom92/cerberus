import { saveResult } from "../db.js";
import { offlineUrlFlags, FLAG_LABELS as URL_FLAG_LABELS, FLAG_POINTS as URL_FLAG_POINTS } from "./urlModule.js";

const URGENCY_WORDS = [
  "urgente", "urgent", "inmediat", "immediat", "suspendid", "suspended",
  "bloquead", "blocked", "ultimas horas", "last hours", "24 horas", "24 hours",
  "expira", "expires", "caduca", "act now", "actua ya", "limited time",
  "tiempo limitado",
];

const CREDENTIAL_WORDS = [
  "verifica tu cuenta", "verify your account", "actualiza tus datos", "update your details",
  "confirma tu identidad", "confirm your identity", "codigo de verificacion", "verification code",
  "contraseña", "password", "pin de seguridad", "security pin", "introduce tu", "enter your",
];

const LURE_WORDS = [
  "has ganado", "you won", "premio", "prize", "reembolso", "refund",
  "paquete retenido", "package held", "aduana", "customs", "factura pendiente", "pending invoice",
  "impago", "unpaid",
];

// Registro/aviso "oficial" vago — muy común en smishing que suplanta administraciones públicas
// (Seg. Social, Correos, DGT, Agencia Tributaria): tono burocrático en vez de urgencia agresiva.
const OFFICIAL_NOTICE_WORDS = [
  "actualizacion pendiente", "tramite pendiente", "gestione el tramite", "gestione su tramite",
  "consulte su informacion", "notificacion pendiente", "aviso importante", "accion requerida",
  "action required", "pending procedure", "gestion pendiente",
];

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly"];

// Marca mencionada en el texto -> dominio real esperado. Si el mensaje nombra la marca
// pero el enlace no apunta a ese dominio, es spoofing casi seguro (ver mailModule.js para el mismo patrón sobre From).
const BRAND_DOMAINS = {
  "seg social": "seg-social.es",
  "seguridad social": "seg-social.es",
  "correos": "correos.es",
  "dgt": "dgt.es",
  "agencia tributaria": "agenciatributaria.gob.es",
  "hacienda": "agenciatributaria.gob.es",
  "bbva": "bbva.com",
  "santander": "santander.com",
  "caixabank": "caixabank.com",
  "paypal": "paypal.com",
  "amazon": "amazon.es",
  "dhl": "dhl.com",
  "ups": "ups.com",
  "fedex": "fedex.com",
  "netflix": "netflix.com",
  "whatsapp": "whatsapp.com",
};

const FLAG_POINTS = {
  brand_domain_mismatch: 40,
  credential_request: 30,
  lure_language: 20,
  official_notice_language: 20,
  urgency_language: 15,
  shortened_url: 15,
  multiple_urls: 10,
  ...URL_FLAG_POINTS,
};

export const SMS_FLAG_LABELS = {
  brand_domain_mismatch: "Menciona una entidad conocida pero el enlace no apunta a su dominio real — suplantación",
  credential_request: "Pide verificar cuenta, contraseña o código — patrón clásico de phishing",
  lure_language: "Usa gancho de premio, reembolso o paquete retenido para generar clic",
  official_notice_language: "Tono de aviso oficial/burocrático vago ('trámite pendiente') sin detalles verificables",
  urgency_language: "Lenguaje de urgencia/presión temporal — táctica común de smishing",
  shortened_url: "Contiene un enlace acortado — oculta el destino real",
  multiple_urls: "Contiene más de un enlace",
  ...URL_FLAG_LABELS,
};

function normalize(s) {
  return s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}

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
  const norm = normalize(text);
  return words.some((w) => norm.includes(normalize(w)));
}

function mentionedBrandDomains(text) {
  const norm = normalize(text);
  return Object.entries(BRAND_DOMAINS)
    .filter(([brand]) => norm.includes(normalize(brand)))
    .map(([, domain]) => domain);
}

export async function checkSms(rawText) {
  const flags = [];
  const urls = extractUrls(rawText);

  if (matchesAny(rawText, CREDENTIAL_WORDS)) flags.push("credential_request");
  if (matchesAny(rawText, LURE_WORDS)) flags.push("lure_language");
  if (matchesAny(rawText, URGENCY_WORDS)) flags.push("urgency_language");
  if (matchesAny(rawText, OFFICIAL_NOTICE_WORDS)) flags.push("official_notice_language");
  if (urls.length > 1) flags.push("multiple_urls");

  const urlDetails = [];
  const urlHosts = [];
  for (const raw of urls) {
    const { href, flags: uFlags } = await offlineUrlFlags(raw);
    urlDetails.push({ raw, href, flags: uFlags });
    for (const f of uFlags) if (!flags.includes(f)) flags.push(f);
    try {
      const host = new URL(href).hostname.replace(/^www\./, "");
      urlHosts.push(host);
      if (SHORTENERS.includes(host) && !flags.includes("shortened_url")) flags.push("shortened_url");
    } catch {
      /* ignore */
    }
  }

  const expectedDomains = mentionedBrandDomains(rawText);
  if (expectedDomains.length > 0 && urlHosts.length > 0) {
    const anyMatch = urlHosts.some((host) => expectedDomains.some((d) => host === d || host.endsWith(`.${d}`)));
    if (!anyMatch) flags.push("brand_domain_mismatch");
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
