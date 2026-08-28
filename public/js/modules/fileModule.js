import { detectSignature, readHeader, extOf, sha256Hex, shannonEntropy, readEntropySample } from "../magicBytes.js";
import { saveResult } from "../db.js";

const HASH_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB — evita bloquear el hilo en móvil con archivos enormes
const HIGH_ENTROPY_THRESHOLD = 7.5; // bits/byte, de 8 máx — típico de datos empaquetados/cifrados

// Extensiones que ejecutan código al abrirlas.
const EXECUTABLE_EXTS = new Set([
  "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "ps1", "jar", "apk", "app", "dmg", "sh", "run", "hta", "cpl", "lnk",
]);
// Extensiones que la gente asocia a "documento inofensivo".
const DOCUMENT_EXTS = new Set([
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt",
  "jpg", "jpeg", "png", "gif", "webp", "heic", "mp3", "mp4", "zip", "rar",
]);

// "factura.pdf.exe" es el disfraz más antiguo del mundo y antes pasaba limpio: la extensión
// real (.exe) coincide con el contenido (PE), así que no había discrepancia que detectar.
// Lo que delata al fichero no es el contenido, es el nombre: aparenta ser un documento.
function doubleExtensionFlag(filename) {
  const parts = filename.toLowerCase().split(".");
  if (parts.length < 3) return null;
  const finalExt = parts[parts.length - 1].trim();
  // Se recorren las extensiones intermedias: cubre "factura.pdf     .exe" y "x.pdf.zip.exe".
  const middle = parts.slice(1, -1).map((p) => p.trim());
  if (EXECUTABLE_EXTS.has(finalExt) && middle.some((m) => DOCUMENT_EXTS.has(m))) {
    return "double_extension";
  }
  return null;
}

export async function checkFile(file) {
  const bytes = await readHeader(file);
  const sig = detectSignature(bytes);
  const declaredExt = extOf(file.name);

  const flags = [];
  let verdict = "safe";

  if (!sig) {
    flags.push("unknown_signature");
    verdict = "unknown";
  } else {
    const extMatches = declaredExt && sig.ext.includes(declaredExt);
    if (declaredExt && !extMatches) {
      flags.push(sig.executable ? "executable_disguised" : "extension_mismatch");
      verdict = "dangerous";
    }
  }

  const doubleExt = doubleExtensionFlag(file.name);
  if (doubleExt) {
    flags.push(doubleExt);
    verdict = "dangerous";
  }

  // Un ejecutable cuya extensión no engaña sigue siendo un ejecutable: conviene avisar
  // de que ese fichero, al abrirlo, ejecuta código.
  if (sig?.executable && !flags.includes("executable_disguised") && !doubleExt) {
    flags.push("is_executable");
    // Sin extensión no hay forma de saber por el nombre qué es: un ejecutable presentado
    // así ("instalador", "documento") oculta su naturaleza igual que uno disfrazado.
    if (!declaredExt) {
      flags.push("executable_no_extension");
      if (verdict === "safe") verdict = "suspicious";
    }
  }

  const entropySample = await readEntropySample(file);
  const entropy = shannonEntropy(entropySample);
  // La entropía alta por sí sola NO es peligrosa: prácticamente todo instalador legítimo
  // (NSIS, Inno Setup, Electron…) va comprimido y supera el umbral. Antes esto marcaba
  // "dangerous" cualquier instalador descargado. Se informa, pero no cambia el veredicto:
  // solo agrava cuando el archivo ADEMÁS venía disfrazado con otra extensión.
  if (sig?.executable && entropy > HIGH_ENTROPY_THRESHOLD) {
    flags.push("packed_executable");
  }

  const hash = file.size <= HASH_SIZE_LIMIT ? await sha256Hex(file) : null;

  const result = {
    type: "file",
    input: file.name,
    size: file.size,
    declaredExt: declaredExt || "(sin extensión)",
    detected: sig ? sig.name : "Desconocido",
    executable: sig ? sig.executable : false,
    entropy: Math.round(entropy * 100) / 100,
    sha256: hash,
    flags,
    verdict,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "file",
    input: file.name,
    verdict,
    riskScore: verdict === "dangerous" ? 90 : verdict === "unknown" ? 0 : 0,
    flags,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}

export const FILE_FLAG_LABELS = {
  unknown_signature: "No se reconoce la firma del archivo (formato no catalogado o corrupto)",
  extension_mismatch: "La extensión no coincide con el contenido real del archivo",
  executable_disguised: "Es un ejecutable disfrazado con otra extensión — alto riesgo",
  double_extension: "Doble extensión: el nombre aparenta ser un documento pero termina en una extensión que ejecuta código — disfraz clásico de malware",
  is_executable: "Este archivo ejecuta código al abrirlo. Ábrelo solo si sabes con certeza de dónde viene",
  executable_no_extension: "Es un ejecutable sin extensión: por el nombre no hay forma de saber que lo es",
  packed_executable: "Ejecutable comprimido o empaquetado. Es lo normal en instaladores, pero también se usa para evadir antivirus — dato informativo, no una alerta por sí solo",
};
