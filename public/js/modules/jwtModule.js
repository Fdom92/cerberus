function base64UrlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(str.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder("utf-8").decode(bytes);
}

export const JWT_FLAG_LABELS = {
  alg_none: "alg=none — el token no está firmado, cualquiera puede fabricarlo",
  expired: "El token ya expiró (exp en el pasado)",
  not_yet_valid: "El token aún no es válido (nbf en el futuro)",
  no_exp: "El token no tiene fecha de expiración (exp) — nunca caduca",
  weak_alg: "Algoritmo débil o poco recomendado",
};

export function decodeJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length < 2) throw new Error("No parece un JWT válido (se esperan 2-3 partes separadas por '.')");

  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));
  const hasSignature = parts.length === 3 && parts[2].length > 0;

  const flags = [];
  const now = Math.floor(Date.now() / 1000);

  if ((header.alg || "").toLowerCase() === "none") flags.push("alg_none");
  else if (["hs1", "rs1", "none"].includes((header.alg || "").toLowerCase())) flags.push("weak_alg");

  if (payload.exp !== undefined) {
    if (payload.exp < now) flags.push("expired");
  } else {
    flags.push("no_exp");
  }
  if (payload.nbf !== undefined && payload.nbf > now) flags.push("not_yet_valid");

  return { header, payload, hasSignature, flags };
}
