import { saveResult } from "../db.js";

const FLAG_POINTS = {
  homograph: 50,
  typosquat: 50,
  ip_literal: 40,
  at_symbol: 30,
  no_https: 30,
  excess_subdomains: 15,
  domain_new: 40,
  resolve_failed: 10,
  domain_age_unknown: 0,
};

const FLAG_LABELS = {
  homograph: "Dominio en punycode / posible homógrafo (caracteres que imitan letras latinas)",
  typosquat: "Muy parecido a un dominio conocido — posible typosquatting",
  ip_literal: "El host es una IP directa, no un dominio",
  at_symbol: "Contiene '@' — el navegador ignora todo lo anterior, puede ocultar el host real",
  no_https: "No usa HTTPS",
  excess_subdomains: "Demasiados guiones o subdominios — patrón típico de phishing",
  domain_new: "Dominio registrado hace menos de 30 días",
  resolve_failed: "No se pudo resolver el destino final (timeout o bloqueo)",
  domain_age_unknown: "No se pudo determinar la edad del dominio",
};

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

function parseUrl(raw) {
  let input = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(input)) input = "https://" + input;
  return new URL(input);
}

function offlineHeuristics(url, knownDomains) {
  const flags = [];
  const host = url.hostname;

  if (url.protocol !== "https:") flags.push("no_https");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) flags.push("ip_literal");
  if (url.href.includes("@") && /@/.test(url.href.split("//")[1] || "")) flags.push("at_symbol");
  if (host.includes("xn--") || /[^\x00-\x7F]/.test(host)) flags.push("homograph");

  const hyphenCount = (host.match(/-/g) || []).length;
  const subdomainCount = host.split(".").length - 2;
  if (hyphenCount > 3 || subdomainCount > 3) flags.push("excess_subdomains");

  const bareHost = host.replace(/^www\./, "");
  for (const known of knownDomains) {
    if (bareHost === known) continue;
    const dist = levenshtein(bareHost, known);
    if (dist > 0 && dist <= 1) {
      flags.push("typosquat");
      break;
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
  }

  const { riskScore, verdict } = scoreFlags(flags);

  const result = {
    type: "url",
    input: url.href,
    finalUrl,
    httpCode,
    ageDays,
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
