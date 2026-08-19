const TAG_TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

function readAscii(view, offset, count) {
  const bytes = [];
  for (let i = 0; i < count; i++) {
    const b = view.getUint8(offset + i);
    if (b === 0) break;
    bytes.push(b);
  }
  return new TextDecoder("ascii").decode(new Uint8Array(bytes));
}

function readRational(view, offset, littleEndian) {
  const num = view.getUint32(offset, littleEndian);
  const den = view.getUint32(offset + 4, littleEndian);
  return den === 0 ? 0 : num / den;
}

function readEntryValue(view, tiffStart, entryOffset, littleEndian) {
  const type = view.getUint16(entryOffset + 2, littleEndian);
  const count = view.getUint32(entryOffset + 4, littleEndian);
  const size = (TAG_TYPE_SIZE[type] || 1) * count;
  const dataOffset = size <= 4 ? entryOffset + 8 : tiffStart + view.getUint32(entryOffset + 8, littleEndian);

  if (type === 2) return readAscii(view, dataOffset, count);
  if (type === 3) {
    const vals = [];
    for (let i = 0; i < count; i++) vals.push(view.getUint16(dataOffset + i * 2, littleEndian));
    return count === 1 ? vals[0] : vals;
  }
  if (type === 4) {
    const vals = [];
    for (let i = 0; i < count; i++) vals.push(view.getUint32(dataOffset + i * 4, littleEndian));
    return count === 1 ? vals[0] : vals;
  }
  if (type === 5) {
    const vals = [];
    for (let i = 0; i < count; i++) vals.push(readRational(view, dataOffset + i * 8, littleEndian));
    return count === 1 ? vals[0] : vals;
  }
  return null;
}

function readIfd(view, tiffStart, ifdOffset, littleEndian) {
  const tags = new Map();
  const entryCount = view.getUint16(ifdOffset, littleEndian);
  for (let i = 0; i < entryCount; i++) {
    const entryOffset = ifdOffset + 2 + i * 12;
    const tag = view.getUint16(entryOffset, littleEndian);
    tags.set(tag, readEntryValue(view, tiffStart, entryOffset, littleEndian));
  }
  const nextOffset = view.getUint32(ifdOffset + 2 + entryCount * 12, littleEndian);
  return { tags, nextOffset };
}

function gpsToDecimal(dms, ref) {
  if (!Array.isArray(dms) || dms.length !== 3) return null;
  const [deg, min, sec] = dms;
  let decimal = deg + min / 60 + sec / 3600;
  if (ref === "S" || ref === "W") decimal = -decimal;
  return decimal;
}

function findApp1(view) {
  if (view.getUint16(0) !== 0xffd8) return null;
  let offset = 2;
  while (offset < view.byteLength - 4) {
    const marker = view.getUint16(offset);
    if ((marker & 0xff00) !== 0xff00) break;
    const segLength = view.getUint16(offset + 2);
    if (marker === 0xffe1) {
      const start = offset + 4;
      const tag = new TextDecoder("ascii").decode(new Uint8Array(view.buffer, start, 6));
      if (tag.startsWith("Exif")) return start + 6;
    }
    if (marker === 0xffda) break; // start of scan, no more metadata segments
    offset += 2 + segLength;
  }
  return null;
}

export function parseExif(arrayBuffer) {
  const view = new DataView(arrayBuffer);
  const tiffStart = findApp1(view);
  if (tiffStart === null) return { hasExif: false };

  const byteOrder = view.getUint16(tiffStart);
  const littleEndian = byteOrder === 0x4949;
  const ifd0Offset = tiffStart + view.getUint32(tiffStart + 4, littleEndian);
  const { tags: ifd0 } = readIfd(view, tiffStart, ifd0Offset, littleEndian);

  const result = {
    hasExif: true,
    make: ifd0.get(0x010f) || null,
    model: ifd0.get(0x0110) || null,
    dateTime: ifd0.get(0x0132) || null,
    orientation: ifd0.get(0x0112) || null,
    gps: null,
  };

  const exifIfdOffset = ifd0.get(0x8769);
  if (exifIfdOffset) {
    try {
      const { tags: exifTags } = readIfd(view, tiffStart, tiffStart + exifIfdOffset, littleEndian);
      if (exifTags.get(0x9003)) result.dateTimeOriginal = exifTags.get(0x9003);
    } catch {
      /* ignore */
    }
  }

  const gpsIfdOffset = ifd0.get(0x8825);
  if (gpsIfdOffset) {
    try {
      const { tags: gpsTags } = readIfd(view, tiffStart, tiffStart + gpsIfdOffset, littleEndian);
      const lat = gpsToDecimal(gpsTags.get(0x0002), gpsTags.get(0x0001));
      const lon = gpsToDecimal(gpsTags.get(0x0004), gpsTags.get(0x0003));
      if (lat !== null && lon !== null) result.gps = { lat, lon };
    } catch {
      /* ignore */
    }
  }

  return result;
}
