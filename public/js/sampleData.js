function u16(n) {
  return [n & 0xff, (n >> 8) & 0xff];
}
function u32(n) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}

// ---- text samples ----
export const SAMPLES = {
  urlSafe: "https://github.com/anthropics",
  urlMalicious: "http://192.168.1.1@goog1e-verify.com/reset",

  mailSafe:
    "From: Alice <alice@example.com>\nReturn-Path: alice@example.com\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nHola, nos vemos mañana.",
  mailMalicious:
    'From: "PayPal Support" <security@paypa1-verify.ru>\nReturn-Path: bounce@another-domain.com\nAuthentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n\nTu cuenta ha sido suspendida, verifica aquí.',

  smsSafe: "Hola, ¿nos vemos a las 8 en el bar de siempre?",
  smsMalicious: "URGENTE: tu paquete está retenido en aduana, paga aquí http://bit.ly/abc123 o se cancelará",

  decodeSample: "SGVsbG8gbXVuZG8sIGVzdG8gZXMgdW5hIHBydWViYQ==",

  secretsClean: "function add(a, b) {\n  return a + b;\n}",
  secretsDirty:
    'const AWS_KEY = "AKIAABCDEFGHIJKLMNOP";\nSTRIPE_KEY = "sk_live_51H8xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n-----BEGIN RSA PRIVATE KEY-----',

  passwordWeak: "123456",
  passwordStrong: "Xk9#mQ2$vL7pR!4z",

  jwtSafe: (() => {
    const b64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return b64url({ alg: "HS256", typ: "JWT" }) + "." + b64url({ sub: "1234", exp: Math.floor(Date.now() / 1000) + 3600 }) + ".sig";
  })(),
  jwtMalicious: (() => {
    const b64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    return b64url({ alg: "none", typ: "JWT" }) + "." + b64url({ sub: "1234", exp: Math.floor(Date.now() / 1000) - 100 }) + ".";
  })(),
};

// ---- file builders ----
function buildZip(entries) {
  const parts = [];
  const centralParts = [];
  let offset = 0;
  const enc = new TextEncoder();
  for (const e of entries) {
    const localOffset = offset;
    const nameBytes = enc.encode(e.name);
    const local = new Uint8Array([
      ...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
      ...u32(0), ...u32(e.data.length), ...u32(e.data.length),
      ...u16(nameBytes.length), ...u16(0), ...nameBytes, ...e.data,
    ]);
    parts.push(local);
    offset += local.length;
    const central = new Uint8Array([
      ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
      ...u32(0), ...u32(e.data.length), ...u32(e.data.length),
      ...u16(nameBytes.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0),
      ...u32(localOffset), ...nameBytes,
    ]);
    centralParts.push(central);
  }
  const cdStart = offset;
  let cdSize = 0;
  for (const c of centralParts) {
    parts.push(c);
    offset += c.length;
    cdSize += c.length;
  }
  const eocd = new Uint8Array([
    ...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(entries.length), ...u16(entries.length),
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

function buildAxml(packageName, permissions) {
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

function buildBinaryPlist(dict) {
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
  const objs = [null];
  const keyIdx = [];
  const valIdx = [];
  for (const [k, v] of entries) {
    keyIdx.push(objs.length);
    objs.push(encodeStringObj(k));
    valIdx.push(objs.length);
    objs.push(encodeStringObj(String(v)));
  }
  objs[0] = [0xd0 | entries.length, ...keyIdx, ...valIdx];
  const header = [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74, 0x30, 0x30];
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
  trailer[6] = 1;
  trailer[7] = 1;
  setBE8(trailer, 8, objs.length);
  setBE8(trailer, 16, 0);
  setBE8(trailer, 24, offsetTableOffset);
  return new Uint8Array([...header, ...objectBytes, ...offsets, ...trailer]);
}

const TINY_JPEG_BODY_HEX =
  "ffdb004300030202030203020304030304050805050404050a070706080c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113141515150c0f171816141812141514ffc0000b080001000101011100ffc4001f0000010501010101010100000000000000000102030405060708090a0bffc400b5100002010303020403050504040000017d01020300041105122131410613516107227114328191a1082342b1c11552d1f02433627282090a161718191a25262728292a3435363738393a434445464748494a535455565758595a636465666768696a737475767778797a838485868788898a92939495969798999aa2a3a4a5a6a7a8a9aab2b3b4b5b6b7b8b9bac2c3c4c5c6c7c8c9cad2d3d4d5d6d7d8d9dae1e2e3e4e5e6e7e8e9eaf1f2f3f4f5f6f7f8f9faffda0008010100003f00fbfa28a2803fffd9";

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}

function buildJpeg({ withGps }) {
  const le = true;
  let extra = [];
  function pushExtra(bytes) {
    const m = { bytes, resolvedOffset: null };
    extra.push(m);
    return m;
  }
  const enc = (s) => new TextEncoder().encode(s + "\0");
  const makeBytes = enc("Apple");
  const modelBytes = enc("iPhone14,5");
  const dtBytes = enc("2025:11:03 18:24:10");
  const makeMarker = pushExtra(makeBytes);
  const modelMarker = pushExtra(modelBytes);
  const dtMarker = pushExtra(dtBytes);

  const ifd0Entries = [
    { tag: 0x010f, type: 2, count: makeBytes.length, marker: makeMarker },
    { tag: 0x0110, type: 2, count: modelBytes.length, marker: modelMarker },
    { tag: 0x0132, type: 2, count: dtBytes.length, marker: dtMarker },
  ];

  let gpsEntries = [];
  let gpsIfdOffset = 0;
  if (withGps) {
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
    const lonRef = enc("E");
    const latMarker = pushExtra(rational3([[40, 1], [25, 1], [4159, 100]]));
    const lonMarker = pushExtra(rational3([[3, 1], [42, 1], [1234, 100]]));
    gpsEntries = [
      { tag: 0x0001, type: 2, count: latRef.length, inline: latRef },
      { tag: 0x0002, type: 5, count: 3, marker: latMarker },
      { tag: 0x0003, type: 2, count: lonRef.length, inline: lonRef },
      { tag: 0x0004, type: 5, count: 3, marker: lonMarker },
    ];
    ifd0Entries.push({ tag: 0x8825, type: 4, count: 1, value: -1 }); // placeholder, offset fixed below
  }

  const ifd0Count = ifd0Entries.length;
  const ifd0Size = 2 + ifd0Count * 12 + 4;
  const ifd0Offset = 8;
  let extraOffset = ifd0Offset + ifd0Size;

  if (withGps) {
    gpsIfdOffset = extraOffset;
    const gpsSize = 2 + gpsEntries.length * 12 + 4;
    extraOffset += gpsSize;
    ifd0Entries.find((e) => e.tag === 0x8825).value = gpsIfdOffset;
  }

  const allMarkers = [
    makeMarker,
    modelMarker,
    dtMarker,
    ...gpsEntries.filter((e) => e.marker).map((e) => e.marker),
  ];
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
      } else if (e.marker) {
        dv.setUint32(eo + 8, e.marker.resolvedOffset, le);
      } else if (e.value !== undefined) {
        dv.setUint32(eo + 8, e.value, le);
      }
    });
    dv.setUint32(offset + 2 + entries.length * 12, nextOffset, le);
  }

  writeIfd(ifd0Offset, ifd0Entries, 0);
  if (withGps) writeIfd(gpsIfdOffset, gpsEntries, 0);
  for (const m of allMarkers) u8.set(m.bytes, m.resolvedOffset);

  const exifHeader = new TextEncoder().encode("Exif\0\0");
  const app1Payload = new Uint8Array(exifHeader.length + u8.length);
  app1Payload.set(exifHeader, 0);
  app1Payload.set(u8, exifHeader.length);
  const app1Len = app1Payload.length + 2;

  const tinyJpegBody = hexToBytes(TINY_JPEG_BODY_HEX);
  const out = new Uint8Array(2 + 2 + 2 + app1Payload.length + tinyJpegBody.length);
  let p = 0;
  out[p++] = 0xff;
  out[p++] = 0xd8;
  out[p++] = 0xff;
  out[p++] = 0xe1;
  out[p++] = (app1Len >> 8) & 0xff;
  out[p++] = app1Len & 0xff;
  out.set(app1Payload, p);
  p += app1Payload.length;
  out.set(tinyJpegBody, p);
  return out;
}

function buildMinimalPdf(text) {
  const content = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
5 0 obj
<< /Length 44 >>
stream
BT /F1 12 Tf 10 50 Td (${text}) Tj ET
endstream
endobj
xref
0 6
0000000000 65535 f
trailer
<< /Size 6 /Root 1 0 R >>
startxref
0
%%EOF
`;
  return new TextEncoder().encode(content);
}

export function sampleSafePdfFile() {
  return new File([buildMinimalPdf("Factura de prueba - documento real")], "factura-real.pdf", { type: "application/pdf" });
}

export function sampleDisguisedFile() {
  const peBytes = new Uint8Array([0x4d, 0x5a, ...new Array(200).fill(0x90)]);
  return new File([peBytes], "factura-falsa.pdf");
}

export function sampleGpsPhotoFile() {
  return new File([buildJpeg({ withGps: true })], "foto-con-gps.jpg", { type: "image/jpeg" });
}

export function sampleCleanPhotoFile() {
  return new File([buildJpeg({ withGps: false })], "foto-sin-gps.jpg", { type: "image/jpeg" });
}

export function sampleSpywareApkFile() {
  const axml = buildAxml("com.suspicious.freegame", [
    "android.permission.READ_SMS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
  ]);
  const dex = new TextEncoder().encode(
    "some binary filler data AKIAABCDEFGHIJKLMNOP more filler junk bytes here padding out the file a bit"
  );
  const zip = buildZip([
    { name: "AndroidManifest.xml", data: axml },
    { name: "classes.dex", data: dex },
  ]);
  return new File([zip], "app-sospechosa-android.apk");
}

export function sampleSpywareIpaFile() {
  const plist = buildBinaryPlist({
    CFBundleIdentifier: "com.suspicious.freegame",
    NSMicrophoneUsageDescription: "Necesitamos el micro todo el rato",
    NSContactsUsageDescription: "Necesitamos tus contactos",
  });
  const binary = new TextEncoder().encode(
    "filler binary data ghp_1234567890abcdefghijklmnopqrstuvwxyz12 more filler bytes padding"
  );
  const zip = buildZip([
    { name: "Payload/App.app/Info.plist", data: plist },
    { name: "Payload/App.app/App", data: binary },
  ]);
  return new File([zip], "app-sospechosa-ios.ipa");
}
