const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

function findEocd(view) {
  for (let i = view.byteLength - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === EOCD_SIG) return i;
  }
  throw new Error("No es un ZIP válido (no se encontró el End Of Central Directory)");
}

export function listZipEntries(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const eocd = findEocd(view);
  const entryCount = view.getUint16(eocd + 10, true);
  let cdOffset = view.getUint32(eocd + 16, true);

  const entries = new Map();
  const decoder = new TextDecoder("utf-8");

  for (let i = 0; i < entryCount; i++) {
    if (view.getUint32(cdOffset, true) !== CENTRAL_SIG) break;
    const method = view.getUint16(cdOffset + 10, true);
    const compressedSize = view.getUint32(cdOffset + 20, true);
    const uncompressedSize = view.getUint32(cdOffset + 24, true);
    const filenameLength = view.getUint16(cdOffset + 28, true);
    const extraLength = view.getUint16(cdOffset + 30, true);
    const commentLength = view.getUint16(cdOffset + 32, true);
    const localHeaderOffset = view.getUint32(cdOffset + 42, true);
    const nameBytes = new Uint8Array(arrayBuffer, cdOffset + 46, filenameLength);
    const name = decoder.decode(nameBytes);

    entries.set(name, { method, compressedSize, uncompressedSize, localHeaderOffset });
    cdOffset += 46 + filenameLength + extraLength + commentLength;
  }
  return entries;
}

async function inflateRaw(bytes) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("Este navegador no soporta DecompressionStream (necesario para ZIP comprimido)");
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

export async function extractZipEntry(arrayBuffer, entry) {
  const view = new DataView(arrayBuffer);
  const off = entry.localHeaderOffset;
  if (view.getUint32(off, true) !== LOCAL_SIG) throw new Error("Cabecera local ZIP inválida");
  const filenameLength = view.getUint16(off + 26, true);
  const extraLength = view.getUint16(off + 28, true);
  const dataStart = off + 30 + filenameLength + extraLength;
  const compressed = new Uint8Array(arrayBuffer, dataStart, entry.compressedSize);

  if (entry.method === 0) return compressed.slice();
  if (entry.method === 8) return inflateRaw(compressed);
  throw new Error(`Método de compresión ZIP no soportado (${entry.method})`);
}
