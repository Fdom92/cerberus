import { saveResult } from "../db.js";
import { analyzeHostnameScripts, punycodeToUnicode } from "../punycode.js";
import { BRAND_DOMAINS } from "../brandDomains.js";
import { checkDomainReputation } from "../reputation.js";

const FLAG_POINTS = {
  // Aparecer en listas de amenazas no es una heurística sobre la forma del dominio: es un
  // hecho contrastado sobre ESE dominio. Por sí solo debe bastar para marcar peligro.
  threat_intel_blocked: 80,
  homograph: 50,
  typosquat: 50,
  executable_link: 55,
  shortened_url: 20,
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
  // Casi todo el phishing se sirve desde dominios de menos de seis meses, pero un negocio
  // legítimo recién montado también es reciente: 20 puntos NO llegan solos al umbral de
  // sospecha (30). Solo pesa acompañado de otra señal, que es exactamente lo que se quiere.
  domain_recent: 20,
  resolve_failed: 0,
  resolve_rate_limited: 0,
  domain_age_unknown: 0,
};

const FLAG_LABELS = {
  threat_intel_blocked:
    "Este dominio está en las listas de phishing/malware de Cloudflare. No es una sospecha por la forma del enlace: está reportado como malicioso. No lo abras",
  executable_link: "El enlace apunta directamente a un archivo que ejecuta código al abrirlo",
  shortened_url: "Es un enlace acortado: oculta a dónde lleva de verdad, y sin abrirlo no hay forma de saberlo",
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
  domain_recent: "Dominio registrado hace menos de 6 meses — no es sospechoso por sí solo, pero casi todas las campañas de phishing usan dominios recientes",
  resolve_rate_limited: "Se ha alcanzado el límite diario de consultas del servicio que resuelve enlaces (25 al día). Vuelve a intentarlo mañana o usa la vista previa del acortador",
  resolve_failed: "No se pudo averiguar el destino final. Es una limitación de esta app (funciona sin servidor propio y depende de proxies públicos poco fiables), no una señal sobre el enlace",
  domain_age_unknown: "No se pudo determinar la edad del dominio. Es una limitación de la consulta, no una señal sobre el enlace",
};

// TLDs con abuso desproporcionado en campañas de phishing (baratos, registro sin verificación).
// Fuentes: informes anuales Interisle/Spamhaus de TLDs más abusados.
const SUSPICIOUS_TLDS = new Set([
  "cfd", "xyz", "top", "click", "link", "work", "support", "icu", "cyou", "rest",
  "quest", "sbs", "gq", "tk", "ml", "ga", "cf", "zip", "mov", "country", "stream",
  "gdn", "kim", "loan", "men", "party", "review", "science", "trade", "win", "date",
  "faith", "accountant", "bar", "cam", "buzz", "rocks", "cc",
]);

// Acortadores: ocultan el destino. La lista vivía solo en smsModule, así que analizar el
// mismo enlace en el módulo de URLs no decía nada.
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
  "cutt.ly", "bit.do", "tiny.cc", "shorturl.at", "s.id", "rb.gy", "v.gd", "tr.im",
  "shrtco.de", "x.co", "acortar.link",
]);

// Página de vista previa OFICIAL de cada acortador: muestra a dónde lleva sin seguir el
// enlace. No podemos leerla nosotros (no tiene CORS), pero sí dársela al usuario para que
// la abra: aterriza en el propio acortador, no en el destino. Avisar de "esto es un
// acortador" sin ofrecer esto no le sirve de nada a nadie.
const SHORTENER_PREVIEW = {
  "bit.ly": (u) => `${u.origin}${u.pathname}+`,
  "tinyurl.com": (u) => `https://preview.tinyurl.com${u.pathname}`,
  "is.gd": (u) => `https://is.gd/preview.php?url=${encodeURIComponent(u.href)}`,
  "v.gd": (u) => `https://v.gd/preview.php?url=${encodeURIComponent(u.href)}`,
  "ow.ly": (u) => `${u.origin}${u.pathname}+`,
  "cutt.ly": (u) => `${u.origin}${u.pathname}+`,
};

export function shortenerPreviewUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    const host = u.hostname.replace(/^www\./, "");
    return SHORTENER_PREVIEW[host] ? SHORTENER_PREVIEW[host](u) : null;
  } catch {
    return null;
  }
}

// Extensiones que ejecutan código: un enlace que apunta directamente a una de ellas es
// descarga de malware, no una página. Cazó el correo de "factura adjunta" que pasaba limpio.
// Sin 'js' ni 'com': todas las webs cargan .js, y cualquier query que acabe en un correo
// ("?email=juan@example.com") termina en ".com". Ambos daban falsos positivos.
const EXECUTABLE_URL_EXT = /\.(exe|scr|pif|bat|cmd|msi|msp|vbs|vbe|wsf|ps1|jar|apk|hta|cpl|lnk|iso|img|dmg)($|[?#])/i;

let knownDomainsCache = null;
// known-domains.json y BRAND_DOMAINS eran dos listas separadas que se habían desincronizado:
// bbva.com estaba en una y bbva.es en la otra, y ningún banco español, bizum.es, renfe.es ni
// movistar.es entraban en la comparación de typosquatting. Se unen aquí para que haya una
// sola fuente y no vuelvan a separarse. (Mismo fallo que ya se documentó entre smsModule y
// mailModule; ver docs/superpowers/specs.)
async function getKnownDomains() {
  if (knownDomainsCache) return knownDomainsCache;
  let base = [];
  try {
    const res = await fetch(new URL("../../data/known-domains.json", import.meta.url));
    base = await res.json();
  } catch {
    base = [];
  }
  const marcas = Object.values(BRAND_DOMAINS).flat();
  knownDomainsCache = [...new Set([...base, ...marcas])];
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
    let brandTokenPresent = [...tokens].some((t) => hostTokens.includes(t) || host.split(".").includes(t));

    // Los dominios de phishing pegan la marca a otras palabras ("sedeseg-social.online"),
    // así que el token exacto no aparece. Se busca como subcadena, pero SOLO en etiquetas
    // compuestas (con guión): así "amazonas.com", que es una palabra suelta que contiene
    // "amazon", no salta.
    if (!brandTokenPresent && registrableFirstLabel.includes("-")) {
      const flat = registrableFirstLabel.replace(/-/g, "");
      brandTokenPresent = [...tokens].some((t) => t.length >= 5 && flat.includes(t.replace(/-/g, "")));
    }

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

  const bare = host.replace(/^www\./, "");
  if (SHORTENERS.has(bare)) flags.push("shortened_url");
  if (EXECUTABLE_URL_EXT.test(url.pathname + url.search)) flags.push("executable_link");

  flags.push(...brandImpersonationFlags(host));

  // El umbral se bajó a 1 porque a distancia 2 chocaban marcas legítimas entre sí
  // (github.com/gitlab.com, x.com/t.co). La causa real era comparar dos dominios que
  // ESTÁN AMBOS en la lista: si el host ya es un dominio conocido, no hay nada que sospechar.
  // Con esa guarda se puede volver a 2 y así se cazan cosas como "payypall.com".
  // Se compara la forma DECODIFICADA y sin tildes: "xn--crreos-9va.es" es "córreos.es",
  // que a la vista es "correos.es". En punycode la distancia de edición es enorme y se
  // colaba; sin tildes es una coincidencia exacta con un dominio conocido.
  const bareHost = host.replace(/^www\./, "");
  const unicodeHost = punycodeToUnicode(bareHost);
  const deaccented = unicodeHost.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  if (deaccented !== bareHost && knownDomains.includes(deaccented)) {
    if (!flags.includes("homograph")) flags.push("homograph");
  }

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

// Resolver el destino de un enlace acortado desde el navegador parecía imposible: los proxies
// CORS públicos están caídos (allorigins devuelve 522), limitados (429) o piden clave, y los dos
// servicios que dan la cadena completa (unshorten.me, redirect-checker.net) no mandan cabeceras
// CORS. Microlink sí: `access-control-allow-origin: *`, sin registro, y devuelve `data.url`
// con el destino ya resuelto tras seguir todas las redirecciones.
//
// Límite comprobado: 25 consultas al día por IP. De sobra para uso personal (nadie comprueba
// 25 enlaces sospechosos al día), pero hay que tratar el 429 con un mensaje claro.
//
// Lo que NO da es el detalle salto a salto: para eso sí haría falta un backend propio. El
// destino final, que es lo que de verdad importa para decidir si abrir un enlace, sí.
async function viaMicrolink(url) {
  const endpoint = `https://api.microlink.io/?url=${encodeURIComponent(url)}&meta=false&insights=false`;
  const res = await fetchWithTimeout(endpoint, 12000);
  if (res.status === 429) throw new Error("rate_limited");
  if (!res.ok) throw new Error("bad_status");
  const data = await res.json();
  const finalUrl = data?.data?.url;
  if (!finalUrl) throw new Error("no_url");
  return { finalUrl, httpCode: null };
}

async function viaAllorigins(url) {
  const res = await fetchWithTimeout("https://api.allorigins.win/get?url=" + encodeURIComponent(url), 6000);
  const data = await res.json();
  const finalUrl = data?.status?.url;
  if (!finalUrl) throw new Error("no-url");
  return { finalUrl, httpCode: data?.status?.http_code ?? null };
}

async function resolveDestination(url) {
  let rateLimited = false;
  for (const attempt of [viaMicrolink, viaAllorigins]) {
    try {
      const result = await attempt(url);
      if (result.finalUrl) return { ...result, rateLimited: false };
    } catch (e) {
      if (e.message === "rate_limited") rateLimited = true;
    }
  }
  return { finalUrl: null, httpCode: null, rateLimited };
}

// La edad del dominio es una de las señales más fuertes que existen: casi todo el phishing
// vive en dominios registrados hace poco. Estaba silenciosamente rota — se consultaba RDAP
// con el hostname COMPLETO, y RDAP solo entiende el dominio registrable: "www.google.com"
// devolvía 404, así que cualquier URL con subdominio (o sea, casi todas) acababa en
// "edad desconocida" y la señal no llegaba a aplicarse nunca.
// Cuando un TLD no está en RDAP no hay nada que consultar: no es un fallo, es que ese
// registro no publica los datos. Se distingue de un fallo real para no dar una alarma
// que el usuario no puede resolver.
async function ageViaRdap(domain) {
  const res = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, 9000);
  // rdap.org redirige al servidor del registro. Un 404 SIN redirección significa que ese TLD
  // no tiene servidor RDAP (.es y .eu, entre otros); con redirección, que el dominio no existe.
  if (res.status === 404 && !res.redirected) return { days: null, reason: "tld_sin_rdap" };
  if (!res.ok) return { days: null, reason: "sin_datos" };
  const data = await res.json();
  const registration = (data.events || []).find((e) => e.eventAction === "registration");
  if (!registration) return { days: null, reason: "sin_datos" };
  const ts = new Date(registration.eventDate).getTime();
  if (!Number.isFinite(ts)) return { days: null, reason: "sin_datos" };
  return { days: Math.round((Date.now() - ts) / 86400000), reason: null, source: "rdap" };
}

// Para los TLD sin RDAP (.es, .eu) queda Certificate Transparency: el primer certificado
// emitido para un dominio acota su edad por arriba. No es la fecha de registro, pero para
// distinguir "de esta semana" de "de hace años" sirve, y es un registro público y auditable.
//
// crt.sh no permite limitar resultados en el servidor, y un dominio veterano puede devolver
// megabytes. Se lee en streaming con un tope: si lo supera, la respuesta MISMA es la señal
// (tantísimos certificados = historial largo = no es reciente) y se corta la descarga.
const CRTSH_MAX_BYTES = 250000;

async function ageViaCertLog(domain) {
  const res = await fetchWithTimeout(
    `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
    12000
  );
  if (!res.ok || !res.body) return { days: null, reason: "sin_datos" };

  // fetchWithTimeout solo cubre hasta las cabeceras: sin esto, un servidor que empieza a
  // responder y luego se atasca dejaba la lectura colgada sin límite.
  const limite = Date.now() + 10000;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let texto = "";
  let bytes = 0;
  let truncado = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (Date.now() > limite) {
      await reader.cancel();
      return { days: null, reason: "sin_datos" };
    }
    bytes += value.byteLength;
    if (bytes > CRTSH_MAX_BYTES) {
      truncado = true;
      await reader.cancel();
      break;
    }
    texto += decoder.decode(value, { stream: true });
  }
  if (truncado) return { days: null, reason: "historial_largo" };

  let registros;
  try {
    registros = JSON.parse(texto);
  } catch {
    return { days: null, reason: "sin_datos" };
  }
  if (!Array.isArray(registros) || registros.length === 0) {
    return { days: null, reason: "sin_certificados" };
  }
  const fechas = registros.map((r) => r.not_before).filter(Boolean).sort();
  const ts = new Date(fechas[0]).getTime();
  if (!Number.isFinite(ts)) return { days: null, reason: "sin_datos" };
  return { days: Math.round((Date.now() - ts) / 86400000), reason: null, source: "ct" };
}

// Devuelve { days, source, reason }. `days` null NO significa sospecha: significa que no se
// sabe, y así se dice. Un dominio conocido no se consulta — es gasto y latencia para
// confirmar lo que ya sabemos, y en crt.sh son megabytes.
async function domainAge(hostname, knownDomains) {
  const domain = registrableDomain(hostname);
  if (Array.isArray(knownDomains) && knownDomains.includes(domain)) {
    return { days: null, source: null, reason: "dominio_conocido" };
  }
  try {
    const rdap = await ageViaRdap(domain);
    if (rdap.days !== null) return { ...rdap, domain };
    if (rdap.reason !== "tld_sin_rdap") return { ...rdap, source: null, domain };
  } catch {
    /* se intenta el registro de certificados igualmente */
  }
  try {
    const ct = await ageViaCertLog(domain);
    return { ...ct, source: ct.source || null, domain };
  } catch {
    return { days: null, source: null, reason: "sin_datos", domain };
  }
}

function scoreFlags(flags) {
  const riskScore = Math.min(100, flags.reduce((sum, f) => sum + (FLAG_POINTS[f] || 0), 0));
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";
  return { riskScore, verdict };
}

export async function checkUrl(rawInput, { networkEnabled, persist = true } = {}) {
  const url = parseUrl(rawInput);
  const knownDomains = await getKnownDomains();
  const flags = offlineHeuristics(url, knownDomains);

  let finalUrl = null;
  let httpCode = null;
  let ageDays = null;
  let ageSource = null;
  let ageReason = null;
  let reputation = null;
  let rateLimited = false;

  if (networkEnabled) {
    const resolved = await resolveDestination(url.href);
    finalUrl = resolved.finalUrl;
    httpCode = resolved.httpCode;
    rateLimited = resolved.rateLimited;
    if (!finalUrl) flags.push(rateLimited ? "resolve_rate_limited" : "resolve_failed");

    // Lo importante de un acortador es a DÓNDE lleva: las heurísticas se vuelven a aplicar
    // sobre el destino resuelto. Si no, un bit.ly que apunta a un dominio de phishing salía
    // limpio, porque bit.ly en sí no tiene nada sospechoso.
    if (finalUrl) {
      try {
        const destino = parseUrl(finalUrl);
        if (destino.hostname !== url.hostname) {
          for (const f of offlineHeuristics(destino, knownDomains)) {
            if (!flags.includes(f)) flags.push(f);
          }
        }
      } catch {
        /* destino no parseable */
      }
    }

    const targetHost = (finalUrl ? (() => { try { return new URL(finalUrl).hostname; } catch { return url.hostname; } })() : url.hostname);
    const edad = await domainAge(targetHost, knownDomains);
    ageDays = edad.days;
    ageSource = edad.source;
    ageReason = edad.reason;
    if (ageDays !== null) {
      if (ageDays < 30) flags.push("domain_new");
      else if (ageDays < 180) flags.push("domain_recent");
    } else if (edad.reason !== "dominio_conocido" && edad.reason !== "historial_largo") {
      // Un dominio conocido o con historial largo de certificados no es una edad "desconocida":
      // en ambos casos se sabe que NO es reciente, que es justo lo que se estaba preguntando.
      flags.push("domain_age_unknown");
    }

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
    ageSource,
    ageReason,
    reputation,
    rateLimited,
    previewUrl: shortenerPreviewUrl(url.href),
    flags,
    riskScore,
    verdict,
    timestamp: Date.now(),
  };

  // El módulo de QR reutiliza este análisis; sin persist=false cada escaneo dejaba dos
  // entradas en el historial, la del QR y la de la URL que lleva dentro.
  if (persist) await saveResult({
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
