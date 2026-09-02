function bytesAt(view, offset, hex) {
  const bytes = hex.split(" ").map((h) => parseInt(h, 16));
  if (offset + bytes.length > view.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (view[offset + i] !== bytes[i]) return false;
  }
  return true;
}

const SIGNATURES = [
  { name: "PDF", mime: "application/pdf", ext: ["pdf"], executable: false, match: (v) => bytesAt(v, 0, "25 50 44 46") },
  { name: "ZIP / Office / APK / JAR", mime: "application/zip", ext: ["zip", "docx", "xlsx", "pptx", "apk", "jar"], executable: false, match: (v) => bytesAt(v, 0, "50 4B 03 04") || bytesAt(v, 0, "50 4B 05 06") || bytesAt(v, 0, "50 4B 07 08") },
  { name: "PNG", mime: "image/png", ext: ["png"], executable: false, match: (v) => bytesAt(v, 0, "89 50 4E 47 0D 0A 1A 0A") },
  { name: "JPEG", mime: "image/jpeg", ext: ["jpg", "jpeg"], executable: false, match: (v) => bytesAt(v, 0, "FF D8 FF") },
  { name: "GIF", mime: "image/gif", ext: ["gif"], executable: false, match: (v) => bytesAt(v, 0, "47 49 46 38") },
  { name: "BMP", mime: "image/bmp", ext: ["bmp"], executable: false, match: (v) => bytesAt(v, 0, "42 4D") },
  { name: "ICO", mime: "image/x-icon", ext: ["ico"], executable: false, match: (v) => bytesAt(v, 0, "00 00 01 00") },
  { name: "ELF (ejecutable Linux)", mime: "application/x-elf", ext: ["elf", "bin", "so"], executable: true, match: (v) => bytesAt(v, 0, "7F 45 4C 46") },
  { name: "PE (ejecutable Windows: exe/dll)", mime: "application/x-msdownload", ext: ["exe", "dll"], executable: true, match: (v) => bytesAt(v, 0, "4D 5A") },
  { name: "OLE/CFB (Office antiguo: doc/xls/ppt, o instalador MSI)", mime: "application/x-ole-storage", ext: ["doc", "xls", "ppt", "msi", "msg", "dot", "xlt", "pps"], executable: true, match: (v) => bytesAt(v, 0, "D0 CF 11 E0 A1 B1 1A E1") },
  { name: "Mach-O / Java class (cabecera ambigua)", mime: "application/x-mach-binary", ext: ["class", "o", "dylib"], executable: true, match: (v) => bytesAt(v, 0, "CA FE BA BE") || bytesAt(v, 0, "FE ED FA CE") || bytesAt(v, 0, "FE ED FA CF") || bytesAt(v, 0, "CF FA ED FE") },
  { name: "RTF", mime: "application/rtf", ext: ["rtf"], executable: false, match: (v) => bytesAt(v, 0, "7B 5C 72 74 66") },
  { name: "GZIP", mime: "application/gzip", ext: ["gz", "gzip", "tgz"], executable: false, match: (v) => bytesAt(v, 0, "1F 8B") },
  { name: "7-Zip", mime: "application/x-7z-compressed", ext: ["7z"], executable: false, match: (v) => bytesAt(v, 0, "37 7A BC AF 27 1C") },
  { name: "RAR", mime: "application/x-rar-compressed", ext: ["rar"], executable: false, match: (v) => bytesAt(v, 0, "52 61 72 21 1A 07") },
  { name: "MP3", mime: "audio/mpeg", ext: ["mp3"], executable: false, match: (v) => bytesAt(v, 0, "49 44 33") || bytesAt(v, 0, "FF FB") },
  // HEIC y AVIF comparten la caja "ftyp" con MP4, así que van antes: si no, MP4 los captura primero.
  { name: "HEIC / HEIF (foto de iPhone)", mime: "image/heic", ext: ["heic", "heif"], executable: false, match: (v) => bytesAt(v, 4, "66 74 79 70") && (bytesAt(v, 8, "68 65 69 63") || bytesAt(v, 8, "68 65 69 78") || bytesAt(v, 8, "6D 69 66 31")) },
  { name: "AVIF", mime: "image/avif", ext: ["avif"], executable: false, match: (v) => bytesAt(v, 4, "66 74 79 70") && bytesAt(v, 8, "61 76 69 66") },
  { name: "MP4 / MOV", mime: "video/mp4", ext: ["mp4", "mov", "m4v"], executable: false, match: (v) => bytesAt(v, 4, "66 74 79 70") },
  { name: "WAV", mime: "audio/wav", ext: ["wav"], executable: false, match: (v) => bytesAt(v, 0, "52 49 46 46") && bytesAt(v, 8, "57 41 56 45") },
  { name: "WebP", mime: "image/webp", ext: ["webp"], executable: false, match: (v) => bytesAt(v, 0, "52 49 46 46") && bytesAt(v, 8, "57 45 42 50") },
  // ISO/IMG: hoy es un formato de entrega de malware muy usado porque el contenido no hereda
  // la marca de "descargado de internet" y se salta el aviso de Windows. La firma va en 0x8001.
  { name: "ISO (imagen de disco)", mime: "application/x-iso9660-image", ext: ["iso"], executable: false, match: (v) => bytesAt(v, 32769, "43 44 30 30 31") || bytesAt(v, 0, "43 44 30 30 31") },
  { name: "SQLite", mime: "application/vnd.sqlite3", ext: ["db", "sqlite", "sqlite3"], executable: false, match: (v) => bytesAt(v, 0, "53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00") },
  { name: "Script (shebang)", mime: "text/x-shellscript", ext: ["sh", "bash", "py", "pl", "rb"], executable: true, match: (v) => bytesAt(v, 0, "23 21") },
];

export function detectSignature(bytes) {
  for (const sig of SIGNATURES) {
    if (sig.match(bytes)) return sig;
  }
  return null;
}

export function readHeader(file, length = 64) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file.slice(0, length));
  });
}

export function extOf(filename) {
  const m = /\.([a-z0-9]+)$/i.exec(filename || "");
  return m ? m[1].toLowerCase() : "";
}

export async function sha256Hex(file) {
  const buf = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const ENTROPY_SAMPLE_BYTES = 256 * 1024;

export function shannonEntropy(bytes) {
  if (bytes.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  for (const c of counts) {
    if (c === 0) continue;
    const p = c / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export async function readEntropySample(file, length = ENTROPY_SAMPLE_BYTES) {
  return readHeader(file, length);
}
