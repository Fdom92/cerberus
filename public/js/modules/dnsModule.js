import { saveResult } from "../db.js";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

async function dohQuery(name, type) {
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${type}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(url, { headers: { Accept: "application/dns-json" }, signal: controller.signal });
    if (!res.ok) throw new Error("DoH query failed");
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

function stripQuotes(s) {
  return s.replace(/^"|"$/g, "");
}

export const DNS_FLAG_LABELS = {
  no_spf: "Sin registro SPF — cualquiera puede falsificar correos 'de' este dominio más fácilmente",
  no_dmarc: "Sin política DMARC — no hay instrucción de qué hacer con correos que fallan SPF/DKIM",
  dmarc_policy_none: "DMARC en modo 'none' — detecta suplantación pero no la bloquea ni la reporta con fuerza",
  domain_not_resolving: "El dominio no resuelve (sin registros A ni MX) — puede no existir o estar mal escrito",
  no_mx_records: "El dominio no tiene servidor de correo: no envía emails legítimos, así que cualquier correo 'de' este dominio es sospechoso",
};

export async function checkDns(rawDomain) {
  const domain = rawDomain
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/^www\./i, "")
    .toLowerCase();

  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    throw new Error("Escribe un dominio válido (ej. ejemplo.com)");
  }

  const [mxRes, txtRes, dmarcRes, aRes] = await Promise.allSettled([
    dohQuery(domain, "MX"),
    dohQuery(domain, "TXT"),
    dohQuery(`_dmarc.${domain}`, "TXT"),
    dohQuery(domain, "A"),
  ]);

  const mxRecords = mxRes.status === "fulfilled" ? (mxRes.value.Answer || []).map((a) => a.data) : [];
  const txtRecords = txtRes.status === "fulfilled" ? (txtRes.value.Answer || []).map((a) => stripQuotes(a.data)) : [];
  const dmarcRecords = dmarcRes.status === "fulfilled" ? (dmarcRes.value.Answer || []).map((a) => stripQuotes(a.data)) : [];
  const aRecords = aRes.status === "fulfilled" ? (aRes.value.Answer || []).map((a) => a.data) : [];

  const spf = txtRecords.find((t) => t.toLowerCase().startsWith("v=spf1")) || null;
  const dmarc = dmarcRecords.find((t) => t.toLowerCase().startsWith("v=dmarc1")) || null;

  const flags = [];
  const sendsEmail = mxRecords.length > 0;

  // Un dominio sin MX no envía correo: que no tenga SPF/DMARC no lo hace sospechoso, es lo
  // esperable en una web normal. Solo se considera un problema si el dominio SÍ tiene correo.
  if (sendsEmail) {
    if (!spf) flags.push("no_spf");
    if (!dmarc) flags.push("no_dmarc");
    else {
      const policy = (/p=(\w+)/i.exec(dmarc) || [])[1]?.toLowerCase();
      if (policy === "none") flags.push("dmarc_policy_none");
    }
  } else if (aRecords.length > 0) {
    flags.push("no_mx_records");
  }
  if (aRecords.length === 0 && mxRecords.length === 0) flags.push("domain_not_resolving");

  const riskScore = Math.min(
    100,
    (flags.includes("no_spf") ? 25 : 0) +
      (flags.includes("no_dmarc") ? 25 : 0) +
      (flags.includes("dmarc_policy_none") ? 15 : 0) +
      (flags.includes("domain_not_resolving") ? 60 : 0)
  );
  const verdict = riskScore >= 60 ? "dangerous" : riskScore >= 25 ? "suspicious" : "safe";

  const result = {
    type: "dns",
    domain,
    mxCount: mxRecords.length,
    spf,
    dmarc,
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "dns",
    input: domain,
    verdict,
    riskScore,
    flags,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}
