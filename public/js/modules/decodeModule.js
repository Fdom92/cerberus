function isMostlyPrintable(str) {
  if (!str) return false;
  let printable = 0;
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if ((code >= 32 && code <= 126) || code >= 160) printable++;
  }
  return printable / str.length > 0.85;
}

function tryUrlDecode(input) {
  try {
    const out = decodeURIComponent(input);
    if (out === input) return null;
    return out;
  } catch {
    return null;
  }
}

function tryBase64Decode(input) {
  const cleaned = input.trim().replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned) || cleaned.length % 4 !== 0) return null;
  try {
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

function tryBase64UrlDecode(input) {
  const cleaned = input.trim();
  if (!/^[A-Za-z0-9_-]+$/.test(cleaned)) return null;
  const std = cleaned.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(cleaned.length / 4) * 4, "=");
  return tryBase64Decode(std);
}

function tryHexDecode(input) {
  const cleaned = input.trim().replace(/\s+/g, "").replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]+$/.test(cleaned) || cleaned.length % 2 !== 0 || cleaned.length < 4) return null;
  try {
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return null;
  }
}

export function decodeAll(input) {
  const results = [];
  const attempts = [
    ["URL-decode", tryUrlDecode],
    ["Base64", tryBase64Decode],
    ["Base64url", tryBase64UrlDecode],
    ["Hex", tryHexDecode],
  ];
  for (const [label, fn] of attempts) {
    const out = fn(input);
    if (out && out !== input && isMostlyPrintable(out)) {
      results.push({ label, value: out });
    }
  }
  return results;
}
