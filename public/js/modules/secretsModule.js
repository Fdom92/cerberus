const PATTERNS = [
  { name: "AWS Access Key ID", severity: "high", re: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret Access Key", severity: "high", re: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi },
  { name: "GitHub token", severity: "high", re: /gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,}/g },
  { name: "GitLab token", severity: "high", re: /glpat-[A-Za-z0-9\-_]{20}/g },
  { name: "Slack token", severity: "high", re: /xox[baprs]-[A-Za-z0-9-]{10,48}/g },
  { name: "Slack webhook", severity: "high", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g },
  { name: "Stripe live secret key", severity: "high", re: /[sr]k_live_[0-9a-zA-Z]{24,}/g },
  // La clave "publishable" de Stripe (pk_live_) NO se incluye: está diseñada para ir en el
  // JavaScript público de la página de pago. Marcarla como secreto filtrado era un falso positivo.
  { name: "Google/Firebase API key", severity: "high", re: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: "Twilio API key", severity: "high", re: /\bSK[0-9a-fA-F]{32}\b/g },
  { name: "SendGrid API key", severity: "high", re: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g },
  { name: "Mailgun API key", severity: "high", re: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { name: "npm token", severity: "high", re: /npm_[A-Za-z0-9]{36}/g },
  { name: "Anthropic API key", severity: "high", re: /sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{20,}/g },
  { name: "OpenAI API key", severity: "high", re: /sk-[A-Za-z0-9]{20,}/g },
  { name: "Private key block", severity: "high", re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { name: "Bearer token en cabecera", severity: "medium", re: /Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}/gi },
  { name: "JWT embebido", severity: "medium", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: "Asignación genérica de secreto", severity: "medium", re: /(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"][A-Za-z0-9_\-/+=]{12,}['"]/gi },
];

function redact(value) {
  if (value.length <= 10) return value.slice(0, 2) + "…" + value.slice(-2);
  return value.slice(0, 4) + "…" + value.slice(-4);
}

// Documentación y ficheros de ejemplo están llenos de claves con la forma correcta pero valor
// falso ("sk-XXXXXXXX", api_key: "YOUR_API_KEY_HERE"). Avisar de esas es ruido que enseña
// a ignorar la herramienta. Se asume que una clave real no es una repetición ni lleva
// literalmente "your"/"example"/"changeme" dentro.
// Deliberadamente conservador: mejor mostrar de vez en cuando un placeholder que ocultar una
// clave real. Por eso NO se filtra por subcadenas que aparecen de forma natural dentro de claves
// legítimas ("abcdef" es hex perfectamente normal, "foo"/"bar" caben en cualquier base64).
const PLACEHOLDER_HINTS =
  /(your|example|placeholder|changeme|change_me|dummy|sample|replace_?me|insert_?your|todo|fixme|xxxx|<|>|\.\.\.)/i;

// Señal fuerte de valor falso: relleno repetido. No depende de que aparezca una palabra
// concreta, así que no puede ocultar una clave real por casualidad.
function isObviouslyFake(value) {
  return /(.)\1{6,}/.test(value) || /(?:xxxx|XXXX)/.test(value) || /[<>]/.test(value) || value.includes("...");
}

// `strict` para los patrones con prefijo de proveedor (AKIA…, ghp_…, sk-ant-…): ahí la
// coincidencia ya es de altísima confianza, y descartarla solo porque el valor contenga
// "your" o "todo" podía ocultar una clave real que llevara esa subcadena por azar.
// Para la regla genérica (`password: "..."`), en cambio, los ejemplos de documentación son
// tan habituales que sí compensa filtrar por palabra.
function looksLikePlaceholder(value, strict) {
  if (isObviouslyFake(value)) return true;
  if (!strict && PLACEHOLDER_HINTS.test(value)) return true;
  return false;
}

// Una clave metida en base64 no la ve ninguna expresión regular del listado. Se decodifican
// las tiras de base64 largas y se vuelve a buscar sobre el resultado. Solo se reporta si lo
// decodificado casa con un patrón de proveedor (los de prefijo, alta confianza): así una
// cadena base64 cualquiera de un fichero de código no genera ruido.
function decodedBase64Text(text) {
  const runs = text.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [];
  const out = [];
  for (const run of runs.slice(0, 200)) {
    if (run.length % 4 !== 0) continue;
    try {
      const decoded = atob(run);
      if (/^[\x20-\x7e\s]+$/.test(decoded)) out.push(decoded);
    } catch {
      /* no era base64 válido */
    }
  }
  return out.join("\n");
}

export function scanSecrets(text) {
  const findings = [];

  const decoded = decodedBase64Text(text);
  if (decoded) {
    for (const { name, re } of PATTERNS) {
      if (name === "Asignación genérica de secreto" || name === "JWT embebido") continue;
      re.lastIndex = 0;
      const m = re.exec(decoded);
      if (m && !looksLikePlaceholder(m[0], true)) {
        findings.push({
          name: `${name} (oculta en base64)`,
          severity: "high",
          count: 1,
          previews: [redact(m[0])],
        });
      }
    }
  }

  for (const { name, severity, re } of PATTERNS) {
    re.lastIndex = 0;
    let match;
    let count = 0;
    const previews = [];
    while ((match = re.exec(text)) && count < 5) {
      if (looksLikePlaceholder(match[0], name !== "Asignación genérica de secreto")) continue;
      previews.push(redact(match[0]));
      count++;
    }
    if (count > 0) findings.push({ name, severity, count, previews });
  }

  const hasHigh = findings.some((f) => f.severity === "high");
  const hasMedium = findings.some((f) => f.severity === "medium");
  const verdict = hasHigh ? "dangerous" : hasMedium ? "suspicious" : "safe";
  const riskScore = hasHigh ? 90 : hasMedium ? 45 : 0;

  return { findings, verdict, riskScore };
}
