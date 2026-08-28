import { detectSignature, readHeader, extOf, sha256Hex, shannonEntropy, readEntropySample } from "../magicBytes.js";
import { saveResult } from "../db.js";

const HASH_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB — evita bloquear el hilo en móvil con archivos enormes
const HIGH_ENTROPY_THRESHOLD = 7.5; // bits/byte, de 8 máx — típico de datos empaquetados/cifrados

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
  packed_executable: "Ejecutable comprimido o empaquetado. Es lo normal en instaladores, pero también se usa para evadir antivirus — dato informativo, no una alerta por sí solo",
};
