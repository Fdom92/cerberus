function u16(n) {
  return [n & 0xff, (n >> 8) & 0xff];
}
function u32(n) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

// ---- Synthetic JPEG with EXIF (Make/Model/DateTime/GPS) ----
export function buildTestJpeg() {
  const le = true;
  let extra = [];
  function pushExtra(bytes) {
    const marker = { bytes, resolvedOffset: null };
    extra.push(marker);
    return marker;
  }
  const enc = (s) => new TextEncoder().encode(s + "\0");

  const makeBytes = enc("ACME");
  const modelBytes = enc("X1");
  const dtBytes = enc("2024:01:01 12:00:00");
  const makeMarker = pushExtra(makeBytes);
  const dtMarker = pushExtra(dtBytes);

  function rational3(vals) {
    const buf = new ArrayBuffer(24);
    const dv = new DataView(buf);
    vals.forEach((v, i) => {
      dv.setUint32(i * 8, v[0], le);
      dv.setUint32(i * 8 + 4, v[1], le);
    });
    return new Uint8Array(buf);
  }
  const latRef = enc("N");
  const lonRef = enc("W");
  const latBytes = rational3([[40, 1], [26, 1], [467, 100]]);
  const lonBytes = rational3([[3, 1], [42, 1], [13, 100]]);
  const latMarker = pushExtra(latBytes);
  const lonMarker = pushExtra(lonBytes);

  const gpsEntries = [
    { tag: 0x0001, type: 2, count: latRef.length, inline: latRef },
    { tag: 0x0002, type: 5, count: 3, marker: latMarker },
    { tag: 0x0003, type: 2, count: lonRef.length, inline: lonRef },
    { tag: 0x0004, type: 5, count: 3, marker: lonMarker },
  ];

  const ifd0Count = 4;
  const ifd0Size = 2 + ifd0Count * 12 + 4;
  const gpsSize = 2 + gpsEntries.length * 12 + 4;
  const ifd0Offset = 8;
  const gpsIfdOffset = ifd0Offset + ifd0Size;
  let extraOffset = gpsIfdOffset + gpsSize;

  const allMarkers = [makeMarker, dtMarker, ...gpsEntries.filter((e) => e.marker).map((e) => e.marker)];
  for (const m of allMarkers) {
    m.resolvedOffset = extraOffset;
    extraOffset += m.bytes.length;
  }
  const totalSize = extraOffset;

  const buf = new ArrayBuffer(totalSize);
  const dv = new DataView(buf);
  const u8 = new Uint8Array(buf);
  u8[0] = 0x49;
  u8[1] = 0x49;
  dv.setUint16(2, 0x002a, le);
  dv.setUint32(4, ifd0Offset, le);

  function writeIfd(offset, entries, nextOffset) {
    dv.setUint16(offset, entries.length, le);
    entries.forEach((e, i) => {
      const eo = offset + 2 + i * 12;
      dv.setUint16(eo, e.tag, le);
      dv.setUint16(eo + 2, e.type, le);
      dv.setUint32(eo + 4, e.count, le);
      if (e.inline) {
        for (let j = 0; j < e.inline.length && j < 4; j++) u8[eo + 8 + j] = e.inline[j];
      } else if (e.value !== undefined) {
        dv.setUint32(eo + 8, e.value, le);
      } else if (e.marker) {
        dv.setUint32(eo + 8, e.marker.resolvedOffset, le);
      }
    });
    dv.setUint32(offset + 2 + entries.length * 12, nextOffset, le);
  }

  writeIfd(
    ifd0Offset,
    [
      { tag: 0x010f, type: 2, count: makeBytes.length, marker: makeMarker },
      { tag: 0x0110, type: 2, count: modelBytes.length, inline: modelBytes },
      { tag: 0x0132, type: 2, count: dtBytes.length, marker: dtMarker },
      { tag: 0x8825, type: 4, count: 1, value: gpsIfdOffset },
    ],
    0
  );
  writeIfd(gpsIfdOffset, gpsEntries, 0);
  for (const m of allMarkers) u8.set(m.bytes, m.resolvedOffset);

  const exifHeader = new TextEncoder().encode("Exif\0\0");
  const app1Payload = new Uint8Array(exifHeader.length + u8.length);
  app1Payload.set(exifHeader, 0);
  app1Payload.set(u8, exifHeader.length);
  const app1Len = app1Payload.length + 2;

  const jpeg = new Uint8Array(2 + 2 + 2 + app1Payload.length + 2);
  let p = 0;
  jpeg[p++] = 0xff;
  jpeg[p++] = 0xd8;
  jpeg[p++] = 0xff;
  jpeg[p++] = 0xe1;
  jpeg[p++] = (app1Len >> 8) & 0xff;
  jpeg[p++] = app1Len & 0xff;
  jpeg.set(app1Payload, p);
  p += app1Payload.length;
  jpeg[p++] = 0xff;
  jpeg[p++] = 0xda;
  return jpeg.buffer;
}

// ---- Synthetic ZIP (stored + deflate entries) ----
export async function buildTestZip(entries) {
  const parts = [];
  const centralParts = [];
  let offset = 0;
  const enc = new TextEncoder();

  const resolved = [];
  for (const e of entries) {
    let data = e.data;
    let method = e.method ?? 0;
    let uncompSize = data.length;
    if (method === 8) {
      uncompSize = data.length;
      const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("deflate-raw"));
      data = new Uint8Array(await new Response(stream).arrayBuffer());
    }
    resolved.push({ name: enc.encode(e.name), data, method, uncompSize });
  }

  for (const e of resolved) {
    const localOffset = offset;
    const local = [
      ...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(e.method), ...u16(0), ...u16(0),
      ...u32(0), ...u32(e.data.length), ...u32(e.uncompSize),
      ...u16(e.name.length), ...u16(0),
      ...e.name, ...e.data,
    ];
    parts.push(new Uint8Array(local));
    offset += local.length;

    const central = [
      ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(e.method), ...u16(0), ...u16(0),
      ...u32(0), ...u32(e.data.length), ...u32(e.uncompSize),
      ...u16(e.name.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0),
      ...u32(localOffset), ...e.name,
    ];
    centralParts.push(new Uint8Array(central));
  }

  const cdStart = offset;
  let cdSize = 0;
  for (const c of centralParts) {
    parts.push(c);
    offset += c.length;
    cdSize += c.length;
  }
  const eocd = new Uint8Array([
    ...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(resolved.length), ...u16(resolved.length),
    ...u32(cdSize), ...u32(cdStart), ...u16(0),
  ]);
  parts.push(eocd);

  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let p = 0;
  for (const part of parts) {
    out.set(part, p);
    p += part.length;
  }
  return out;
}

// ---- Synthetic Android Binary XML (AndroidManifest.xml) ----
export function buildTestAxml(packageName, permissions) {
  const strings = ["manifest", "package", packageName, "uses-permission", "name", ...permissions];

  function buildStringPool(strs) {
    const headerSize = 28;
    const offsetsSize = strs.length * 4;
    const stringsStart = headerSize + offsetsSize;
    let dataBytes = [];
    const offsets = [];
    for (const s of strs) {
      offsets.push(dataBytes.length);
      dataBytes.push(...u16(s.length));
      for (const ch of s) dataBytes.push(...u16(ch.charCodeAt(0)));
      dataBytes.push(...u16(0));
    }
    const totalSize = stringsStart + dataBytes.length;
    const bytes = [];
    bytes.push(...u16(1), ...u16(headerSize), ...u32(totalSize));
    bytes.push(...u32(strs.length), ...u32(0), ...u32(0), ...u32(stringsStart), ...u32(0));
    for (const o of offsets) bytes.push(...u32(o));
    bytes.push(...dataBytes);
    return bytes;
  }
  function buildStartElement(nameIdx, attrs) {
    const size = 36 + attrs.length * 20;
    const bytes = [];
    bytes.push(...u16(0x0102), ...u16(16), ...u32(size));
    bytes.push(...u32(0), ...u32(0xffffffff));
    bytes.push(...u32(0xffffffff), ...u32(nameIdx));
    bytes.push(...u16(20), ...u16(20), ...u16(attrs.length), ...u16(0), ...u16(0), ...u16(0));
    for (const a of attrs) {
      bytes.push(...u32(0xffffffff), ...u32(a.nameIdx), ...u32(a.rawValueIdx));
      bytes.push(...u16(8), 0, 3, ...u32(a.rawValueIdx));
    }
    return bytes;
  }
  function buildEndElement(nameIdx) {
    const bytes = [];
    bytes.push(...u16(0x0103), ...u16(16), ...u32(24));
    bytes.push(...u32(0), ...u32(0xffffffff));
    bytes.push(...u32(0xffffffff), ...u32(nameIdx));
    return bytes;
  }

  const stringPoolBytes = buildStringPool(strings);
  let body = [];
  body.push(...buildStartElement(0, [{ nameIdx: 1, rawValueIdx: 2 }]));
  permissions.forEach((_, i) => {
    body.push(...buildStartElement(3, [{ nameIdx: 4, rawValueIdx: 5 + i }]));
    body.push(...buildEndElement(3));
  });
  body.push(...buildEndElement(0));

  const totalSize = 8 + stringPoolBytes.length + body.length;
  return new Uint8Array([...u16(3), ...u16(8), ...u32(totalSize), ...stringPoolBytes, ...body]);
}

// ---- Synthetic binary plist (bplist00) — flat string dict, e.g. an iOS Info.plist ----
export function buildTestBinaryPlist(dict) {
  function encodeStringObj(str) {
    const bytes = new TextEncoder().encode(str);
    const n = bytes.length;
    const out = [];
    if (n < 15) out.push(0x50 | n);
    else out.push(0x5f, 0x10, n);
    for (const b of bytes) out.push(b);
    return out;
  }
  function setBE8(arr, start, value) {
    for (let i = 7; i >= 0; i--) {
      arr[start + i] = value & 0xff;
      value = Math.floor(value / 256);
    }
  }

  const entries = Object.entries(dict);
  const objs = [null]; // index 0 reserved for the dict itself
  const keyIdx = [];
  const valIdx = [];
  for (const [k, v] of entries) {
    keyIdx.push(objs.length);
    objs.push(encodeStringObj(k));
    valIdx.push(objs.length);
    objs.push(encodeStringObj(String(v)));
  }
  objs[0] = [0xd0 | entries.length, ...keyIdx, ...valIdx];

  const header = [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30]; // "bplist00"
  const objectBytes = [];
  const offsets = [];
  let cursor = header.length;
  for (const o of objs) {
    offsets.push(cursor);
    objectBytes.push(...o);
    cursor += o.length;
  }
  const offsetTableOffset = header.length + objectBytes.length;

  const trailer = new Array(32).fill(0);
  trailer[6] = 1; // offsetIntSize
  trailer[7] = 1; // objectRefSize
  setBE8(trailer, 8, objs.length); // numObjects
  setBE8(trailer, 16, 0); // topObject
  setBE8(trailer, 24, offsetTableOffset);

  return new Uint8Array([...header, ...objectBytes, ...offsets, ...trailer]);
}
