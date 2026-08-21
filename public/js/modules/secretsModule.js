const PATTERNS = [
  { name: "AWS Access Key ID", severity: "high", re: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret Access Key", severity: "high", re: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi },
  { name: "GitHub token", severity: "high", re: /gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,}/g },
  { name: "GitLab token", severity: "high", re: /glpat-[A-Za-z0-9\-_]{20}/g },
  { name: "Slack token", severity: "high", re: /xox[baprs]-[A-Za-z0-9-]{10,48}/g },
  { name: "Slack webhook", severity: "high", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g },
  { name: "Stripe live secret key", severity: "high", re: /[sr]k_live_[0-9a-zA-Z]{24,}/g },
  { name: "Stripe publishable key", severity: "medium", re: /pk_live_[0-9a-zA-Z]{24,}/g },
  { name: "Google/Firebase API key", severity: "high", re: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: "Twilio API key", severity: "high", re: /SK[0-9a-fA-F]{32}/g },
  { name: "SendGrid API key", severity: "high", re: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g },
  { name: "Mailgun API key", severity: "high", re: /key-[0-9a-zA-Z]{32}/g },
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

export function scanSecrets(text) {
  const findings = [];
  for (const { name, severity, re } of PATTERNS) {
    re.lastIndex = 0;
    let match;
    let count = 0;
    const previews = [];
    while ((match = re.exec(text)) && count < 5) {
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
