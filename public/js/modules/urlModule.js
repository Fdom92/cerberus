import { saveResult } from "../db.js";
import { analyzeHostnameScripts } from "../punycode.js";
import { BRAND_DOMAINS } from "../brandDomains.js";
import { checkDomainReputation } from "../reputation.js";

const FLAG_POINTS = {
  // Aparecer en listas de amenazas no es una heurística sobre la forma del dominio: es un
  // hecho contrastado sobre ESE dominio. Por sí solo debe bastar para marcar peligro.
  threat_intel_blocked: 80,
  homograph: 50,
  typosquat: 50,
  brand_subdomain_spoof: 50,
  brand_in_hostname: 35,
  ip_literal: 40,
  at_symbol: 30,
  no_https: 30,
  // Un TLD abusado por sí solo NO basta para sospechar: hay muchísimos sitios legítimos en
  // .xyz/.top/.link (abc.xyz es de Alphabet). Suma, pero no alcanza el umbral en solitario.
  suspicious_tld: 15,
  excess_subdomains: 15,
  domain_new: 40,
  resolve_failed: 10,
  domain_age_unknown: 0,
};

const FLAG_LABELS = {
  threat_intel_blocked:
    "Este dominio está en las listas de phishing/malware de Cloudflare. No es una sospecha por la forma del enlace: está reportado como malicioso. No lo abras",
  homograph: "El dominio usa caracteres que imitan letras latinas — posible homógrafo",
  typosquat: "Muy parecido a un dominio conocido — posible typosquatting",
  brand_subdomain_spoof: "El dominio real no es el de la marca: la marca aparece solo como subdominio, y lo que manda es lo que va justo antes del .com/.es final",
  brand_in_hostname: "Usa el nombre de una entidad conocida dentro de un dominio que no le pertenece",
  ip_literal: "El host es una IP directa, no un dominio",
  at_symbol: "Contiene '@' — el navegador ignora todo lo anterior, puede ocultar el host real",
  no_https: "No usa HTTPS",
  suspicious_tld: "Dominio de nivel superior muy usado en campañas de phishing (barato, sin verificación)",
  excess_subdomains: "Demasiados guiones o subdominios — patrón típico de phishing",
  domain_new: "Dominio registrado hace menos de 30 días",
  resolve_failed: "No se pudo resolver el destino final (timeout o bloqueo)",
  domain_age_unknown: "No se pudo determinar la edad del dominio",
};

// TLDs con abuso desproporcionado en campañas de phishing (baratos, registro sin verificación).
// Fuentes: informes anuales Interisle/Spamhaus de TLDs más abusados.
const SUSPICIOUS_TLDS = new Set([
  "cfd", "xyz", "top", "click", "link", "work", "support", "icu", "cyou", "rest",
  "quest", "sbs", "gq", "tk", "ml", "ga", "cf", "zip", "mov", "country", "stream",
  "gdn", "kim", "loan", "men", "party", "review", "science", "trade", "win", "date",
  "faith", "accountant", "bar", "cam", "buzz", "rocks", "cc",
]);

let knownDomainsCache = null;
async function getKnownDomains() {
  if (knownDomainsCache) return knownDomainsCache;
  try {
    const res = await fetch(new URL("../../data/known-domains.json", import.meta.url));
    knownDomainsCache = await res.json();
  } catch {
    knownDomainsCache = [];
  }
  return knownDomainsCache;
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

// Sufijos de segundo nivel frecuentes: sin esto, el dominio registrable de "dgt.gob.es"
// se calcularía como "gob.es" y la comprobación de marca fallaría.
const SECOND_LEVEL = new Set(["co", "com", "gob", "org", "net", "edu", "gov", "ac", "gov"]);

function registrableDomain(host) {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const last = parts[parts.length - 1];
  const prev = parts[parts.length - 2];
  const take = last.length === 2 && SECOND_LEVEL.has(prev) ? 3 : 2;
  return parts.slice(-take).join(".");
}

// Variantes del nombre de marca tal y como aparecerían en un dominio:
// "seg social" -> "segsocial" y "seg-social".
function brandTokens(brand) {
  return new Set([brand.replace(/\s+/g, ""), brand.replace(/\s+/g, "-")]);
}

// Las dos formas de phishing de dominio más habituales, y las que peor detectaba antes:
//   paypal.com.inicio-sesion.net  -> la marca va de subdominio; el dominio real es el del atacante
//   bbva-clientes-acceso.com      -> el nombre de la marca metido en un dominio ajeno
// La clave para no dar falsos positivos es comparar contra el dominio REGISTRABLE: así
// amazon.de o google.es (internacionales legítimos) no saltan, porque su primera etiqueta
// sigue siendo el nombre de la marca.
function brandImpersonationFlags(host) {
  const flags = [];
  const registrable = registrableDomain(host);
  const registrableFirstLabel = registrable.split(".")[0];

  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    const legit = domains.some((d) => registrable === d || host === d || host.endsWith(`.${d}`));
    if (legit) return []; // es realmente un dominio de la marca

    // A) el dominio de la marca aparece dentro del host pero no es el dominio real
    if (domains.some((d) => host.includes(`${d}.`) || host.includes(`.${d}`))) {
      flags.push("brand_subdomain_spoof");
      break;
    }

    // B) el nombre de la marca aparece como token del host, pero el dominio no es suyo.
    // Se exige token exacto (separado por . o -) para no marcar "amazonas.com" por "amazon".
    const tokens = brandTokens(brand);
    const hostTokens = host.split(/[.-]/);
    const brandTokenPresent = [...tokens].some((t) => hostTokens.includes(t) || host.split(".").includes(t));
    if (brandTokenPresent && !tokens.has(registrableFirstLabel)) {
      flags.push("brand_in_hostname");
      break;
    }
  }
  return flags;
}

function parseUrl(raw) {
  let input = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = "https://" + input;

  let url;
  try {
    url = new URL(input);
  } catch {
    // Sin esto salía a la interfaz el mensaje interno del navegador en inglés
    // ("Failed to construct 'URL'"), que no le dice nada a quien la usa.
    throw new Error("No parece una dirección web válida. Revisa que esté completa.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Solo se pueden analizar direcciones http:// o https:// (esta usa ${url.protocol})`);
  }
  if (!url.hostname) throw new Error("La dirección no incluye ningún dominio.");
  return url;
}

function offlineHeuristics(url, knownDomains) {
  const flags = [];
  const host = url.hostname;

  if (url.protocol !== "https:") flags.push("no_https");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) flags.push("ip_literal");
  // Solo cuenta el '@' de userinfo (https://usuario@host), que es el que oculta el host real.
  // Un '@' en la ruta o la query es normalísimo: emails de contacto, paquetes npm (@1.0.0)…
  if (url.username || url.password) flags.push("at_symbol");
  if (analyzeHostnameScripts(host).suspicious) flags.push("homograph");

  const hyphenCount = (host.match(/-/g) || []).length;
  const subdomainCount = host.split(".").length - 2;
  if (hyphenCount > 3 || subdomainCount > 3) flags.push("excess_subdomains");

  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) flags.push("suspicious_tld");

  flags.push(...brandImpersonationFlags(host));

  // El umbral se bajó a 1 porque a distancia 2 chocaban marcas legítimas entre sí
  // (github.com/gitlab.com, x.com/t.co). La causa real era comparar dos dominios que
  // ESTÁN AMBOS en la lista: si el host ya es un dominio conocido, no hay nada que sospechar.
  // Con esa guarda se puede volver a 2 y así se cazan cosas como "payypall.com".
  const bareHost = host.replace(/^www\./, "");
  const hostFirstLabel = bareHost.split(".")[0];
  // Un subdominio de un dominio conocido (s.correos.es) es el propio dominio conocido.
  const isKnownGood = knownDomains.some((d) => bareHost === d || bareHost.endsWith(`.${d}`));
  if (!isKnownGood) {
    for (const known of knownDomains) {
      // Misma marca en otro país (amazon.de frente a amazon.es) comparte la primera etiqueta
      // y solo cambia el TLD: son 2 ediciones, pero es el dominio legítimo, no un typosquat.
      // Suplantar la marca en OTRO dominio (amazon.evil.com) lo cazan las reglas de marca.
      if (known.split(".")[0] === hostFirstLabel) continue;
      const dist = levenshtein(bareHost, known);
      // Solo se admite distancia 2 en dominios largos: en los cortos, 2 ediciones son
      // media palabra y cualquier dominio no relacionado acabaría pareciéndose.
      const limit = known.length >= 9 ? 2 : 1;
      if (dist > 0 && dist <= limit) {
        flags.push("typosquat");
        break;
      }
    }
  }
  return flags;
}

async function fetchWithTimeout(url, ms) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function viaAllorigins(url) {
  const res = await fetchWithTimeout("https://api.allorigins.win/get?url=" + encodeURIComponent(url), 6000);
  const data = await res.json();
  const finalUrl = data?.status?.url;
  if (!finalUrl) throw new Error("no-url");
  return { finalUrl, httpCode: data?.status?.http_code ?? null };
}

async function viaCorsproxy(url) {
  const res = await fetchWithTimeout("https://corsproxy.io/?url=" + encodeURIComponent(url), 6000);
  if (!res.ok) throw new Error("bad-status");
  return { finalUrl: res.url && res.url !== url ? res.url : null, httpCode: res.status };
}

async function resolveDestination(url) {
  for (const attempt of [viaAllorigins, viaCorsproxy]) {
    try {
      const result = await attempt(url);
      if (result.finalUrl) return result;
    } catch {
      // try next proxy
    }
  }
  return null;
}

async function domainAge(hostname) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`https://rdap.org/domain/${hostname}`, { signal: controller.signal });
    if (!res.ok) return null;
    const data = await res.json();
    const registration = (data.events || []).find((e) => e.eventAction === "registration");
    if (!registration) return null;
    const days = (Date.now() - new Date(registration.eventDate).getTime()) / 86400000;
    return Math.round(days);
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function scoreFlags(flags) {
  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";
  return { riskScore, verdict };
}

export async function checkUrl(rawInput, { networkEnabled }) {
  const url = parseUrl(rawInput);
  const knownDomains = await getKnownDomains();
  const flags = offlineHeuristics(url, knownDomains);

  let finalUrl = null;
  let httpCode = null;
  let ageDays = null;
  let reputation = null;

  if (networkEnabled) {
    const resolved = await resolveDestination(url.href);
    if (resolved) {
      finalUrl = resolved.finalUrl;
      httpCode = resolved.httpCode;
    } else {
      flags.push("resolve_failed");
    }

    const targetHost = (finalUrl ? (() => { try { return new URL(finalUrl).hostname; } catch { return url.hostname; } })() : url.hostname);
    ageDays = await domainAge(targetHost);
    if (ageDays === null) flags.push("domain_age_unknown");
    else if (ageDays < 30) flags.push("domain_new");

    // Se consulta el destino final: de nada sirve mirar la reputación del acortador.
    reputation = (await checkDomainReputation(targetHost)).status;
    if (reputation === "blocked") flags.push("threat_intel_blocked");
  }

  const { riskScore, verdict } = scoreFlags(flags);

  const result = {
    type: "url",
    input: url.href,
    finalUrl,
    httpCode,
    ageDays,
    reputation,
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "url",
    input: url.href,
    verdict,
    riskScore,
    flags,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}

export async function offlineUrlFlags(rawInput) {
  try {
    const url = parseUrl(rawInput);
    const knownDomains = await getKnownDomains();
    return { href: url.href, flags: offlineHeuristics(url, knownDomains) };
  } catch {
    return { href: rawInput, flags: [] };
  }
}

export { FLAG_LABELS, FLAG_POINTS };
