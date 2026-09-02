import { saveResult } from "../db.js";
import { offlineUrlFlags, FLAG_LABELS as URL_FLAG_LABELS, FLAG_POINTS as URL_FLAG_POINTS } from "./urlModule.js";
import { normalize, matchesAny, extractUrls, OFFICIAL_NOTICE_WORDS } from "../textHeuristics.js";
import { BRAND_DOMAINS } from "../brandDomains.js";
import { checkDomainsReputation } from "../reputation.js";

const URGENCY_WORDS = [
  "urgente", "urgent", "inmediat", "immediat", "suspendid", "suspended",
  "bloquead", "blocked", "ultimas horas", "last hours", "24 horas", "24 hours",
  "expira", "expires", "caduca", "act now", "actua ya", "limited time",
  "tiempo limitado",
];

// Solo frases que PIDEN una credencial. Antes incluía "codigo de verificacion", "contraseña" y
// "password" a secas, y eso marcaba como sospechoso el SMS legítimo más común que existe:
// "Tu código de verificación es 847362" o "Tu contraseña se ha cambiado correctamente".
// Entregar un código es normal; pedir que lo introduzcas en algún sitio es lo que delata phishing.
const CREDENTIAL_WORDS = [
  "verifica tu cuenta", "verify your account", "valida tu cuenta", "validate your account",
  "actualiza tus datos", "update your details", "confirma tus datos", "confirm your details",
  "confirma tu identidad", "confirm your identity", "verifica tu identidad",
  "introduce tu", "introduzca su", "enter your", "facilita tus datos", "facilitenos sus datos",
  "reactiva tu cuenta", "reactivate your account", "identificate en", "inicia sesion en el siguiente",
  "necesitamos tu contraseña", "we need your password", "confirma tu contraseña",
];

const LURE_WORDS = [
  "has ganado", "you won", "premio", "prize", "reembolso", "refund",
  "paquete retenido", "package held", "aduana", "customs", "factura pendiente", "pending invoice",
  "impago", "unpaid",
];

// Estafa del "hijo en apuros": no lleva enlace, no menciona ninguna marca y no usa palabras
// de urgencia clásicas, así que no dejaba ninguna señal. El patrón es constante: alguien dice
// ser un familiar, anuncia un número nuevo y acaba pidiendo dinero.
const FAMILY_WORDS = ["hola mama", "hola papa", "soy tu hijo", "soy tu hija", "hola soy tu"];
const NEW_NUMBER_WORDS = [
  "numero nuevo", "nuevo numero", "este es mi numero", "se me ha roto el movil",
  "se me rompio el movil", "he cambiado de numero", "mi nuevo numero", "movil nuevo",
];
const MONEY_WORDS = [
  "pago", "transferencia", "bizum", "ingreso", "dinero", "pagar", "abonar", "urgente",
];

const SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
  "cutt.ly", "bit.do", "tiny.cc", "shorturl.at", "s.id", "rb.gy", "v.gd", "tr.im", "shrtco.de", "x.co",
];

export const SMS_FLAG_POINTS = {
  threat_intel_blocked: 80,
  family_impersonation: 45,
  brand_domain_mismatch: 40,
  callback_number: 30,
  credential_request: 30,
  lure_language: 20,
  official_notice_language: 20,
  urgency_language: 15,
  shortened_url: 15,
  multiple_urls: 10,
  ...URL_FLAG_POINTS,
};

export const SMS_FLAG_LABELS = {
  family_impersonation: "Alguien dice ser un familiar desde un número nuevo y acaba pidiendo dinero. Es la estafa del 'hijo en apuros': verifica llamando al número que YA tenías guardado, nunca a este",
  brand_domain_mismatch: "Menciona una entidad conocida pero el enlace no apunta a su dominio real — suplantación",
  callback_number: "Te pide llamar a un número por un problema con tu cuenta. Es la estafa telefónica clásica: nunca llames al número del mensaje, busca el oficial por tu cuenta",
  credential_request: "Pide verificar cuenta, contraseña o código — patrón clásico de phishing",
  lure_language: "Usa gancho de premio, reembolso o paquete retenido para generar clic",
  official_notice_language: "Tono de aviso oficial/burocrático vago ('trámite pendiente') sin detalles verificables",
  urgency_language: "Lenguaje de urgencia/presión temporal — táctica común de smishing",
  shortened_url: "Contiene un enlace acortado — oculta el destino real",
  multiple_urls: "Contiene más de un enlace",
  ...URL_FLAG_LABELS,
};

function mentionedBrandDomains(text) {
  // También sin espacios ni puntos: "Seg. Social" y "Pay Pal" tienen que contar como
  // mención de la marca, o separar la palabra es una evasión de un solo carácter.
  const norm = normalize(text);
  const compact = norm.replace(/[\s.]+/g, "");
  return Object.entries(BRAND_DOMAINS)
    .filter(([brand]) => {
      const b = normalize(brand);
      return norm.includes(b) || compact.includes(b.replace(/\s+/g, ""));
    })
    .flatMap(([, domains]) => domains);
}

export async function checkSms(rawText, { networkEnabled = false, persist = true } = {}) {
  const flags = [];
  const urls = extractUrls(rawText);

  if (matchesAny(rawText, CREDENTIAL_WORDS)) flags.push("credential_request");
  if (matchesAny(rawText, LURE_WORDS)) flags.push("lure_language");
  if (matchesAny(rawText, URGENCY_WORDS)) flags.push("urgency_language");
  if (matchesAny(rawText, OFFICIAL_NOTICE_WORDS)) flags.push("official_notice_language");
  if (urls.length > 1) flags.push("multiple_urls");

  // Vishing: sin enlace no había casi nada que analizar, pero "su cuenta está bloqueada,
  // llame a este número" es una estafa muy extendida y no dejaba ninguna señal.
  // Familiar + número nuevo + petición de dinero: dos de los tres bastan, porque los
  // mensajes reales no siempre traen los tres en el primer envío.
  const famSignals =
    (matchesAny(rawText, FAMILY_WORDS) ? 1 : 0) +
    (matchesAny(rawText, NEW_NUMBER_WORDS) ? 1 : 0) +
    (matchesAny(rawText, MONEY_WORDS) ? 1 : 0);
  if (famSignals >= 2) flags.push("family_impersonation");

  const hasPhone = /(?:\+34[\s-]?)?(?:\d[\s-]?){9,}/.test(rawText);
  const problemContext = matchesAny(rawText, [
    "cuenta", "tarjeta", "bloque", "suspend", "seguridad", "fraude", "cargo", "account", "card",
  ]);
  if (hasPhone && problemContext && urls.length === 0) flags.push("callback_number");

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

  // Solo si el usuario ha activado las comprobaciones de red: consultar la reputación
  // implica enviar el dominio del enlace a Cloudflare, y este módulo es offline por defecto.
  let reputations = [];
  if (networkEnabled && urlHosts.length > 0) {
    reputations = await checkDomainsReputation(urlHosts);
    if (reputations.some((r) => r.status === "blocked")) flags.push("threat_intel_blocked");
  }

  const expectedDomains = mentionedBrandDomains(rawText);
  if (expectedDomains.length > 0 && urlHosts.length > 0) {
    const anyMatch = urlHosts.some((host) => expectedDomains.some((d) => host === d || host.endsWith(`.${d}`)));
    if (!anyMatch) flags.push("brand_domain_mismatch");
  }

  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (SMS_FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";

  const result = {
    type: "sms",
    text: rawText,
    urls: urlDetails,
    reputations,
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  if (persist) await saveResult({
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
