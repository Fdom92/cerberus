function readLen16(view, off) {
  const c0 = view.getUint16(off, true);
  if (c0 & 0x8000) {
    const c1 = view.getUint16(off + 2, true);
    return { len: ((c0 & 0x7fff) << 16) | c1, bytesRead: 4 };
  }
  return { len: c0, bytesRead: 2 };
}

function readLen8(view, off) {
  const b0 = view.getUint8(off);
  if (b0 & 0x80) {
    const b1 = view.getUint8(off + 1);
    return { len: ((b0 & 0x7f) << 8) | b1, bytesRead: 2 };
  }
  return { len: b0, bytesRead: 1 };
}

function readStringAt(view, base, utf8Flag) {
  if (utf8Flag) {
    const charLen = readLen8(view, base);
    const byteOff = base + charLen.bytesRead;
    const byteLen = readLen8(view, byteOff);
    const start = byteOff + byteLen.bytesRead;
    const bytes = new Uint8Array(view.buffer, start, byteLen.len);
    return new TextDecoder("utf-8").decode(bytes);
  }
  const charLen = readLen16(view, base);
  const start = base + charLen.bytesRead;
  let str = "";
  for (let i = 0; i < charLen.len; i++) str += String.fromCharCode(view.getUint16(start + i * 2, true));
  return str;
}

const CHUNK_STRING_POOL = 0x0001;
const CHUNK_START_ELEMENT = 0x0102;

export function parseManifest(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  let pos = view.getUint16(2, true); // headerSize of the top XML chunk

  let stringPool = [];
  let packageName = null;
  const permissions = [];

  while (pos < view.byteLength - 8) {
    const type = view.getUint16(pos, true);
    const size = view.getUint32(pos + 4, true);
    if (size <= 0) break;
    const chunkStart = pos;

    if (type === CHUNK_STRING_POOL) {
      const stringCount = view.getUint32(chunkStart + 8, true);
      const flags = view.getUint32(chunkStart + 16, true);
      const stringsStart = view.getUint32(chunkStart + 20, true);
      const utf8Flag = (flags & 0x100) !== 0;
      const offsetsBase = chunkStart + 28;
      stringPool = [];
      for (let k = 0; k < stringCount; k++) {
        const off = view.getUint32(offsetsBase + k * 4, true);
        stringPool.push(readStringAt(view, chunkStart + stringsStart + off, utf8Flag));
      }
    } else if (type === CHUNK_START_ELEMENT) {
      const nameIdx = view.getUint32(chunkStart + 20, true);
      const attrStart = view.getUint16(chunkStart + 24, true);
      const attrSize = view.getUint16(chunkStart + 26, true);
      const attrCount = view.getUint16(chunkStart + 28, true);
      const firstAttrOffset = chunkStart + 16 + attrStart;
      const tagName = stringPool[nameIdx];

      const attrs = [];
      for (let a = 0; a < attrCount; a++) {
        const ao = firstAttrOffset + a * attrSize;
        const attrNameIdx = view.getUint32(ao + 4, true);
        const attrRawValueIdx = view.getUint32(ao + 8, true);
        const typedDataType = view.getUint8(ao + 15);
        const typedData = view.getUint32(ao + 16, true);
        const name = stringPool[attrNameIdx];
        let value;
        if (attrRawValueIdx !== 0xffffffff) value = stringPool[attrRawValueIdx];
        else if (typedDataType === 3) value = stringPool[typedData];
        else value = typedData;
        attrs.push({ name, value });
      }

      if (tagName === "manifest") {
        const pkg = attrs.find((a) => a.name === "package");
        if (pkg) packageName = pkg.value;
      }
      if (tagName === "uses-permission" || tagName === "uses-permission-sdk-23") {
        const nameAttr = attrs.find((a) => a.name === "name");
        if (nameAttr) permissions.push(nameAttr.value);
      }
    }

    pos = chunkStart + size;
  }

  return { package: packageName, permissions: [...new Set(permissions)] };
}
