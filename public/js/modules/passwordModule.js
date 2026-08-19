const COMMON_PASSWORDS = new Set([
  "123456", "12345678", "123456789", "password", "contraseña", "qwerty", "qwerty123",
  "111111", "12345", "1234567", "1234567890", "admin", "welcome", "letmein",
  "iloveyou", "abc123", "000000", "1q2w3e4r", "monkey", "dragon", "football",
  "baseball", "master", "hello", "login", "princess", "solo", "starwars",
  "passw0rd", "trustno1", "hola1234", "contraseña123", "usuario", "cambiar123",
]);

function hasSequential(pw) {
  const seqs = ["abcdefghijklmnopqrstuvwxyz", "01234567890"];
  const lower = pw.toLowerCase();
  for (const seq of seqs) {
    for (let i = 0; i <= seq.length - 4; i++) {
      if (lower.includes(seq.slice(i, i + 4))) return true;
    }
  }
  return false;
}

function hasRepeats(pw) {
  return /(.)\1{2,}/.test(pw);
}

export function estimatePassword(pw) {
  if (!pw) return { entropy: 0, category: "vacía", flags: [] };

  const flags = [];
  let charsetSize = 0;
  if (/[a-z]/.test(pw)) charsetSize += 26;
  if (/[A-Z]/.test(pw)) charsetSize += 26;
  if (/[0-9]/.test(pw)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) charsetSize += 32;
  charsetSize = charsetSize || 1;

  let entropy = pw.length * Math.log2(charsetSize);

  const isCommon = COMMON_PASSWORDS.has(pw.toLowerCase());
  if (isCommon) {
    flags.push("common_password");
    entropy = Math.min(entropy, 10);
  }
  if (hasSequential(pw)) {
    flags.push("sequential_chars");
    entropy -= 10;
  }
  if (hasRepeats(pw)) {
    flags.push("repeated_chars");
    entropy -= 8;
  }
  if (pw.length < 8) flags.push("too_short");

  entropy = Math.max(0, Math.round(entropy));

  let category;
  if (entropy < 28) category = "muy débil";
  else if (entropy < 36) category = "débil";
  else if (entropy < 60) category = "aceptable";
  else if (entropy < 80) category = "fuerte";
  else category = "muy fuerte";

  return { entropy, category, flags, length: pw.length };
}

export const PASSWORD_FLAG_LABELS = {
  common_password: "Está en la lista de contraseñas más usadas del mundo",
  sequential_chars: "Contiene una secuencia obvia (abcd, 1234…)",
  repeated_chars: "Contiene el mismo carácter repetido 3+ veces seguidas",
  too_short: "Menos de 8 caracteres",
};

async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

// k-anonymity: solo se envían los primeros 5 caracteres del hash SHA-1, nunca la contraseña.
// https://haveibeenpwned.com/API/v3#PwnedPasswords
export async function checkPwnedPassword(pw) {
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { signal: controller.signal });
    if (!res.ok) throw new Error("respuesta no válida");
    const text = await res.text();
    const line = text.split("\n").find((l) => l.startsWith(suffix));
    const count = line ? parseInt(line.split(":")[1], 10) : 0;
    return { checked: true, count, pwned: count > 0 };
  } catch {
    return { checked: false, count: 0, pwned: false };
  } finally {
    clearTimeout(timer);
  }
}
