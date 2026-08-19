function readObjectSize(view, offset) {
  const marker = view.getUint8(offset);
  const lowNibble = marker & 0x0f;
  if (lowNibble !== 0x0f) return { count: lowNibble, next: offset + 1 };
  const intMarker = view.getUint8(offset + 1);
  const byteCount = 1 << (intMarker & 0x0f);
  const count = readUInt(view, offset + 2, byteCount);
  return { count, next: offset + 2 + byteCount };
}

function readUInt(view, offset, byteCount) {
  let value = 0n;
  for (let i = 0; i < byteCount; i++) value = (value << 8n) | BigInt(view.getUint8(offset + i));
  return Number(value);
}

function readObjectAt(view, offset, objectTable, objectRefSize, cache) {
  if (cache.has(offset)) return cache.get(offset);
  const marker = view.getUint8(offset);
  const type = marker & 0xf0;
  let result;

  if (type === 0x00) {
    if (marker === 0x08) result = false;
    else if (marker === 0x09) result = true;
    else result = null;
  } else if (type === 0x10) {
    const byteCount = 1 << (marker & 0x0f);
    result = readUInt(view, offset + 1, byteCount);
  } else if (type === 0x20) {
    const byteCount = 1 << (marker & 0x0f);
    result = byteCount === 4 ? view.getFloat32(offset + 1, false) : view.getFloat64(offset + 1, false);
  } else if (type === 0x30) {
    result = null; // date, not needed
  } else if (type === 0x40) {
    const { count, next } = readObjectSize(view, offset);
    result = new Uint8Array(view.buffer, next, count);
  } else if (type === 0x50) {
    const { count, next } = readObjectSize(view, offset);
    const bytes = new Uint8Array(view.buffer, next, count);
    result = new TextDecoder("ascii").decode(bytes);
  } else if (type === 0x60) {
    const { count, next } = readObjectSize(view, offset);
    let str = "";
    for (let i = 0; i < count; i++) str += String.fromCharCode(view.getUint16(next + i * 2, false));
    result = str;
  } else if (type === 0xa0 || type === 0xc0) {
    const { count, next } = readObjectSize(view, offset);
    const arr = [];
    cache.set(offset, arr);
    for (let i = 0; i < count; i++) {
      const ref = readUInt(view, next + i * objectRefSize, objectRefSize);
      arr.push(readObjectAt(view, objectTable[ref], objectTable, objectRefSize, cache));
    }
    return arr;
  } else if (type === 0xd0) {
    const { count, next } = readObjectSize(view, offset);
    const obj = {};
    cache.set(offset, obj);
    const keyRefs = [];
    for (let i = 0; i < count; i++) keyRefs.push(readUInt(view, next + i * objectRefSize, objectRefSize));
    const valStart = next + count * objectRefSize;
    for (let i = 0; i < count; i++) {
      const valRef = readUInt(view, valStart + i * objectRefSize, objectRefSize);
      const key = readObjectAt(view, objectTable[keyRefs[i]], objectTable, objectRefSize, cache);
      obj[key] = readObjectAt(view, objectTable[valRef], objectTable, objectRefSize, cache);
    }
    return obj;
  } else {
    result = null;
  }

  cache.set(offset, result);
  return result;
}

export function parseBinaryPlist(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const magic = new TextDecoder("ascii").decode(new Uint8Array(arrayBuffer, 0, 8));
  if (magic !== "bplist00") throw new Error("No es un binary plist (falta cabecera bplist00)");

  const trailerStart = view.byteLength - 32;
  const offsetIntSize = view.getUint8(trailerStart + 6);
  const objectRefSize = view.getUint8(trailerStart + 7);
  const numObjects = readUInt(view, trailerStart + 8, 8);
  const topObject = readUInt(view, trailerStart + 16, 8);
  const offsetTableOffset = readUInt(view, trailerStart + 24, 8);

  const objectTable = [];
  for (let i = 0; i < numObjects; i++) {
    objectTable.push(readUInt(view, offsetTableOffset + i * offsetIntSize, offsetIntSize));
  }

  const cache = new Map();
  return readObjectAt(view, objectTable[topObject], objectTable, objectRefSize, cache);
}

function xmlNodeToValue(node) {
  if (!node) return null;
  switch (node.nodeName) {
    case "string":
      return node.textContent;
    case "integer":
      return parseInt(node.textContent, 10);
    case "real":
      return parseFloat(node.textContent);
    case "true":
      return true;
    case "false":
      return false;
    case "array":
      return [...node.children].map(xmlNodeToValue);
    case "dict": {
      const obj = {};
      const children = [...node.children];
      for (let i = 0; i < children.length; i += 2) {
        obj[children[i].textContent] = xmlNodeToValue(children[i + 1]);
      }
      return obj;
    }
    default:
      return null;
  }
}

export function parseXmlPlist(text) {
  const doc = new DOMParser().parseFromString(text, "application/xml");
  if (doc.querySelector("parsererror")) throw new Error("XML plist inválido");
  const root = doc.querySelector("plist > dict, plist > array");
  return xmlNodeToValue(root);
}

export function parsePlist(arrayBuffer) {
  const head = new TextDecoder("ascii").decode(new Uint8Array(arrayBuffer, 0, Math.min(8, arrayBuffer.byteLength)));
  if (head === "bplist00") return parseBinaryPlist(arrayBuffer);
  return parseXmlPlist(new TextDecoder("utf-8").decode(arrayBuffer));
}
