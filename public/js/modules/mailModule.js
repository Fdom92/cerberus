import { saveResult } from "../db.js";

const FLAG_POINTS = {
  display_name_spoof: 50,
  spf_fail: 30,
  dkim_fail: 30,
  dmarc_fail: 30,
  reply_to_mismatch: 25,
  from_returnpath_mismatch: 20,
  spf_missing: 15,
  dkim_missing: 15,
  dmarc_missing: 15,
  auth_results_missing: 10,
};

export const MAIL_FLAG_LABELS = {
  display_name_spoof: "El nombre mostrado imita una marca conocida pero el dominio real no coincide",
  spf_fail: "SPF falló — el servidor de envío no está autorizado por el dominio",
  dkim_fail: "DKIM falló — la firma criptográfica del mensaje no es válida",
  dmarc_fail: "DMARC falló — no cumple la política de autenticación del dominio",
  reply_to_mismatch: "Reply-To apunta a un dominio distinto de From — las respuestas van a otro sitio",
  from_returnpath_mismatch: "From y Return-Path tienen dominios distintos",
  spf_missing: "No se encontró resultado SPF en las cabeceras",
  dkim_missing: "No se encontró resultado DKIM en las cabeceras",
  dmarc_missing: "No se encontró resultado DMARC en las cabeceras",
  auth_results_missing: "No hay cabecera Authentication-Results — no se puede verificar SPF/DKIM/DMARC",
};

const BRAND_DOMAINS = {
  paypal: "paypal.com",
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  amazon: "amazon.com",
  netflix: "netflix.com",
  santander: "santander.com",
  bbva: "bbva.com",
  caixabank: "caixabank.com",
  correos: "correos.es",
  "seguridad social": "seg-social.es",
  "agencia tributaria": "agenciatributaria.gob.es",
  dhl: "dhl.com",
  fedex: "fedex.com",
  ups: "ups.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  whatsapp: "whatsapp.com",
};

function parseHeaders(raw) {
  const headerBlock = raw.split(/\r?\n\r?\n/)[0];
  const lines = headerBlock.split(/\r?\n/);
  const unfolded = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.trim();
    } else {
      unfolded.push(line);
    }
  }
  const map = new Map();
  for (const line of unfolded) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!map.has(name)) map.set(name, []);
    map.get(name).push(value);
  }
  return map;
}

function domainOf(headerValue) {
  if (!headerValue) return null;
  const m = /[\w.+-]+@([\w.-]+)/.exec(headerValue);
  return m ? m[1].toLowerCase() : null;
}

function displayNameOf(headerValue) {
  if (!headerValue) return "";
  const m = /^([^<]+)</.exec(headerValue.trim());
  return m ? m[1].trim().replace(/^"|"$/g, "") : "";
}

function authResult(authRaw, mechanism) {
  const re = new RegExp(mechanism + "=(\\w+)", "i");
  const m = re.exec(authRaw);
  return m ? m[1].toLowerCase() : null;
}

export async function checkMail(rawInput) {
  const headers = parseHeaders(rawInput);
  const flags = [];

  const from = headers.get("from")?.[0] || "";
  const returnPath = headers.get("return-path")?.[0] || "";
  const replyTo = headers.get("reply-to")?.[0] || "";
  const authRaw = (headers.get("authentication-results") || []).join(" ");
  const receivedSpf = headers.get("received-spf")?.[0] || "";

  const fromDomain = domainOf(from);
  const returnPathDomain = domainOf(returnPath);
  const replyToDomain = domainOf(replyTo);
  const displayName = displayNameOf(from).toLowerCase();

  if (authRaw) {
    const spf = authResult(authRaw, "spf");
    const dkim = authResult(authRaw, "dkim");
    const dmarc = authResult(authRaw, "dmarc");
    if (spf === "fail" || spf === "softfail") flags.push("spf_fail");
    else if (!spf && !/pass|fail/i.test(receivedSpf)) flags.push("spf_missing");
    if (dkim === "fail") flags.push("dkim_fail");
    else if (!dkim) flags.push("dkim_missing");
    if (dmarc === "fail") flags.push("dmarc_fail");
    else if (!dmarc) flags.push("dmarc_missing");
  } else if (/fail/i.test(receivedSpf)) {
    flags.push("spf_fail");
  } else {
    flags.push("auth_results_missing");
  }

  if (returnPathDomain && fromDomain && returnPathDomain !== fromDomain) {
    flags.push("from_returnpath_mismatch");
  }
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    flags.push("reply_to_mismatch");
  }

  for (const [brand, domain] of Object.entries(BRAND_DOMAINS)) {
    if (displayName.includes(brand) && fromDomain && !fromDomain.endsWith(domain)) {
      flags.push("display_name_spoof");
      break;
    }
  }

  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";

  const result = {
    type: "mail",
    from,
    fromDomain,
    returnPathDomain,
    replyToDomain,
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "mail",
    input: from || "(cabecera sin From)",
    verdict,
    riskScore,
    flags,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}
