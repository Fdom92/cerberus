import { detectSignature, readHeader, extOf, sha256Hex, shannonEntropy, readEntropySample } from "../magicBytes.js";
import { saveResult } from "../db.js";
import { listZipEntries } from "../zipReader.js";

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
  // 34 KB: suficiente para llegar al descriptor ISO en 0x8001 sin leer el fichero entero.
  const bytes = await readHeader(file, 34000);
  const sig = detectSignature(bytes);
  const declaredExt = extOf(file.name);

  const flags = [];
  let verdict = "safe";
  let result_zipDanger = [];

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

  // El ZIP en sí nunca es "el malware": lo es lo que lleva dentro. Un "Presupuesto.pdf.zip"
  // con un .exe dentro pasaba limpio porque el contenedor es un ZIP legítimo.
  let zipEntries = null;
  if (sig?.mime === "application/zip" && file.size < 30 * 1024 * 1024) {
    try {
      const names = [...listZipEntries(await file.arrayBuffer()).keys()];
      zipEntries = names;
      const peligrosos = names.filter((n) => EXECUTABLE_EXTS.has(extOf(n)));
      const conDobleExt = names.filter((n) => doubleExtensionFlag(n));
      if (peligrosos.length > 0 || conDobleExt.length > 0) {
        flags.push("archive_contains_executable");
        verdict = "dangerous";
        result_zipDanger = [...new Set([...peligrosos, ...conDobleExt])];
      }
    } catch {
      /* ZIP cifrado o malformado: no se puede mirar dentro */
    }
  }

  // ISO/IMG: contenedor legítimo, pero hoy se usa sobre todo para entregar malware porque
  // lo que va dentro no hereda la marca de "descargado de internet" y Windows no avisa.
  // Se marca sospechoso, no peligroso: quien se baja una ISO de Linux verá el aviso y sabrá
  // que no le aplica; quien la recibe por correo tiene justo la advertencia que necesita.
  if (sig?.mime === "application/x-iso9660-image") {
    flags.push("disk_image_delivery");
    if (verdict === "safe") verdict = "suspicious";
  }

  // HTML smuggling: un .html que trae dentro un ejecutable en base64 y lo reconstruye con
  // JavaScript. Para el navegador es "solo una página", y así se salta los filtros de correo.
  if (!sig && /\.html?$/i.test(file.name)) {
    const texto = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 8000));
    const tieneScript = /<script/i.test(texto);
    const reconstruye = /atob\s*\(|base64,|Uint8Array|msSaveOrOpenBlob|createObjectURL/i.test(texto);
    if (tieneScript && reconstruye) {
      flags.push("html_smuggling");
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
    zipEntries,
    zipDangerous: result_zipDanger,
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
  disk_image_delivery: "Imagen de disco (ISO/IMG). Es un formato legítimo, pero se usa mucho para colar malware: lo que va dentro se salta el aviso de Windows de 'archivo descargado de internet'. Si te ha llegado por correo o mensaje, no lo abras",
  html_smuggling: "Página HTML que reconstruye un archivo ejecutable con JavaScript. Es la técnica de 'HTML smuggling': parece una página inofensiva y así evita los filtros de correo",
  archive_contains_executable: "El comprimido contiene un archivo que ejecuta código. El ZIP en sí es inofensivo; lo que lleva dentro no",
  packed_executable: "Ejecutable comprimido o empaquetado. Es lo normal en instaladores, pero también se usa para evadir antivirus — dato informativo, no una alerta por sí solo",
};
