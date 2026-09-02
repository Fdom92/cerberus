import { saveResult } from "../db.js";
import { offlineUrlFlags, FLAG_LABELS as URL_FLAG_LABELS, FLAG_POINTS as URL_FLAG_POINTS } from "./urlModule.js";
import { normalize, matchesAny, extractUrls, OFFICIAL_NOTICE_WORDS } from "../textHeuristics.js";
import { BRAND_DOMAINS } from "../brandDomains.js";
import { checkDomainsReputation } from "../reputation.js";

// Peticiones de datos sensibles: en correo son la carga útil habitual (cambiar la cuenta
// de la nómina, "actualice sus datos bancarios") y no se miraban en absoluto.
const MAIL_CREDENTIAL_WORDS = [
  "actualice sus datos", "actualiza tus datos", "datos bancarios", "verifique su cuenta",
  "verifica tu cuenta", "confirme su identidad", "confirme sus datos", "introduzca sus datos",
  "update your details", "verify your account", "confirm your identity", "banking details",
  "mantengala pulsando", "mantener contraseña", "keep my password", "revalide su",
];

export const MAIL_FLAG_POINTS = {
  threat_intel_blocked: 80,
  credential_request: 30,
  display_name_spoof: 50,
  brand_domain_mismatch: 40,
  spf_fail: 30,
  dkim_fail: 30,
  dmarc_fail: 30,
  // Ojo: un Return-Path o un Reply-To distintos del From son el comportamiento NORMAL de
  // cualquier envío masivo legítimo (Mailchimp, SendGrid) y de cualquier lista de correo.
  // Son señal muy débil por sí solos — suman, pero no bastan para sospechar.
  reply_to_mismatch: 10,
  from_returnpath_mismatch: 8,
  official_notice_language: 20,
  spf_missing: 15,
  dkim_missing: 15,
  dmarc_missing: 15,
  auth_results_missing: 10,
  ...URL_FLAG_POINTS,
};

export const MAIL_FLAG_LABELS = {
  credential_request: "Pide datos bancarios, credenciales o confirmación de identidad — la carga útil típica del phishing por correo",
  display_name_spoof: "El nombre mostrado imita una marca conocida pero el dominio real no coincide",
  brand_domain_mismatch: "El cuerpo menciona una entidad conocida pero sus enlaces no apuntan a su dominio real",
  spf_fail: "SPF falló — el servidor de envío no está autorizado por el dominio",
  dkim_fail: "DKIM falló — la firma criptográfica del mensaje no es válida",
  dmarc_fail: "DMARC falló — no cumple la política de autenticación del dominio",
  reply_to_mismatch: "Reply-To apunta a un dominio distinto de From — las respuestas van a otro sitio",
  from_returnpath_mismatch: "From y Return-Path tienen dominios distintos",
  official_notice_language: "Tono de aviso oficial/burocrático vago ('trámite pendiente') sin detalles verificables",
  spf_missing: "No se encontró resultado SPF en las cabeceras",
  dkim_missing: "No se encontró resultado DKIM en las cabeceras",
  dmarc_missing: "No se encontró resultado DMARC en las cabeceras",
  auth_results_missing: "No hay cabecera Authentication-Results — no se puede verificar SPF/DKIM/DMARC",
  ...URL_FLAG_LABELS,
};

function splitHeadersAndBody(raw) {
  const parts = raw.split(/\r?\n\r?\n/);
  return { headerBlock: parts[0], body: parts.slice(1).join("\n\n") };
}

function parseHeaders(headerBlock) {
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

function mentionedBrandDomains(text) {
  // Se compara también contra el texto sin espacios para que "Pay Pal Seguridad" o
  // "Seg. Social" cuenten como mención de la marca: separar la palabra era una evasión trivial.
  const norm = normalize(text);
  const compact = norm.replace(/[\s.]+/g, "");
  return Object.entries(BRAND_DOMAINS)
    .filter(([brand]) => {
      const b = normalize(brand);
      return norm.includes(b) || compact.includes(b.replace(/\s+/g, ""));
    })
    .flatMap(([, domains]) => domains);
}

export async function checkMail(rawInput, { networkEnabled = false } = {}) {
  const { headerBlock, body } = splitHeadersAndBody(rawInput);
  const headers = parseHeaders(headerBlock);
  const flags = [];

  const from = headers.get("from")?.[0] || "";
  const subject = headers.get("subject")?.[0] || "";
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

  // El asunto se ignoraba por completo, y es justo donde se pone la marca suplantada
  // ("Su cuenta de PayPal ha sido suspendida"). Cuenta igual que el nombre mostrado.
  const identityText = `${displayName} ${subject}`;
  const identityBrands = mentionedBrandDomains(identityText);
  if (identityBrands.length > 0 && fromDomain && !identityBrands.some((d) => fromDomain === d || fromDomain.endsWith(`.${d}`))) {
    flags.push("display_name_spoof");
  }

  // Análisis del cuerpo: cabeceras limpias no bastan si el cuerpo enlaza a otro sitio
  // suplantando una entidad conocida (mismo patrón que smsModule.js sobre el texto del SMS).
  const bodyUrlDetails = [];
  const bodyUrlHosts = [];
  let reputations = [];
  if (body.trim()) {
    // El asunto entra en el análisis de texto: el fraude del CEO pone ahí "Acción requerida"
    // y el cuerpo va limpio, así que mirando solo el cuerpo no saltaba nada.
    if (matchesAny(`${subject}\n${body}`, OFFICIAL_NOTICE_WORDS)) flags.push("official_notice_language");
    if (matchesAny(`${subject}\n${body}`, MAIL_CREDENTIAL_WORDS)) flags.push("credential_request");

    for (const raw of extractUrls(body)) {
      const { href, flags: uFlags } = await offlineUrlFlags(raw);
      bodyUrlDetails.push({ raw, href, flags: uFlags });
      for (const f of uFlags) if (!flags.includes(f)) flags.push(f);
      try {
        bodyUrlHosts.push(new URL(href).hostname.replace(/^www\./, ""));
      } catch {
        /* ignore */
      }
    }

    // Igual que en SMS: solo con las comprobaciones de red activadas, porque implica enviar
    // los dominios enlazados en el correo a Cloudflare.
    if (networkEnabled && bodyUrlHosts.length > 0) {
      reputations = await checkDomainsReputation(bodyUrlHosts);
      if (reputations.some((r) => r.status === "blocked")) flags.push("threat_intel_blocked");
    }

    // Mencionar una marca no es suplantarla: un boletín legítimo dice "síguenos en Facebook"
    // y enlaza a su propio dominio. Solo se marca cuando el mensaje además se PRESENTA como
    // esa entidad — la marca está en el nombre mostrado, o el texto usa tono de aviso oficial.
    const impersonating = identityBrands.length > 0 || flags.includes("official_notice_language");
    const expectedDomains = impersonating ? mentionedBrandDomains(`${identityText} ${body}`) : [];
    if (expectedDomains.length > 0 && bodyUrlHosts.length > 0) {
      const anyMatch = bodyUrlHosts.some((host) => expectedDomains.some((d) => host === d || host.endsWith(`.${d}`)));
      if (!anyMatch && !flags.includes("display_name_spoof")) flags.push("brand_domain_mismatch");
    }
  }

  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (MAIL_FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";

  const result = {
    type: "mail",
    from,
    fromDomain,
    returnPathDomain,
    replyToDomain,
    bodyUrls: bodyUrlDetails,
    reputations,
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
