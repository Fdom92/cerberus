import { scanSecrets } from "./secretsModule.js";
import { saveResult } from "../db.js";
import { listZipEntries, extractZipEntry } from "../zipReader.js";
import { parseManifest } from "../axmlParser.js";
import { parsePlist } from "../plistParser.js";

const DANGEROUS_USAGE_DESCRIPTIONS = {
  NSCameraUsageDescription: "high",
  NSMicrophoneUsageDescription: "high",
  NSContactsUsageDescription: "high",
  NSLocationAlwaysAndWhenInUseUsageDescription: "high",
  NSLocationAlwaysUsageDescription: "high",
  NSHealthShareUsageDescription: "high",
  NSHealthUpdateUsageDescription: "high",
  NSSpeechRecognitionUsageDescription: "high",
  NSLocationWhenInUseUsageDescription: "medium",
  NSPhotoLibraryUsageDescription: "medium",
  NSPhotoLibraryAddUsageDescription: "medium",
  NSBluetoothAlwaysUsageDescription: "medium",
  NSBluetoothPeripheralUsageDescription: "medium",
  NSFaceIDUsageDescription: "medium",
  NSCalendarsUsageDescription: "medium",
  NSRemindersUsageDescription: "medium",
  NSMotionUsageDescription: "medium",
  NSAppleMusicUsageDescription: "medium",
};

const DANGEROUS_PERMISSIONS = {
  "android.permission.READ_SMS": "high",
  "android.permission.RECEIVE_SMS": "high",
  "android.permission.SEND_SMS": "high",
  "android.permission.READ_CALL_LOG": "high",
  "android.permission.WRITE_CALL_LOG": "high",
  "android.permission.PROCESS_OUTGOING_CALLS": "high",
  "android.permission.RECORD_AUDIO": "high",
  "android.permission.CAMERA": "high",
  "android.permission.BIND_ACCESSIBILITY_SERVICE": "high",
  "android.permission.BIND_DEVICE_ADMIN": "high",
  "android.permission.SYSTEM_ALERT_WINDOW": "high",
  "android.permission.REQUEST_INSTALL_PACKAGES": "high",
  "android.permission.READ_CONTACTS": "high",
  "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "high",
  "android.permission.QUERY_ALL_PACKAGES": "high",
  "android.permission.ACCESS_FINE_LOCATION": "medium",
  "android.permission.ACCESS_COARSE_LOCATION": "medium",
  "android.permission.READ_PHONE_STATE": "medium",
  "android.permission.GET_ACCOUNTS": "medium",
  "android.permission.READ_EXTERNAL_STORAGE": "medium",
  "android.permission.WRITE_EXTERNAL_STORAGE": "medium",
};

const MIN_STRING_LEN = 5;
const MAX_BYTES_SCANNED = 20 * 1024 * 1024; // 20MB cap — mantiene el hilo responsive en móvil

function extractAsciiStrings(bytes, minLen = MIN_STRING_LEN) {
  const out = [];
  let start = -1;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    const printable = b >= 0x20 && b <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else if (start !== -1) {
      if (i - start >= minLen) out.push(String.fromCharCode(...bytes.subarray(start, i)));
      start = -1;
    }
  }
  if (start !== -1 && bytes.length - start >= minLen) {
    out.push(String.fromCharCode(...bytes.subarray(start, bytes.length)));
  }
  return out;
}

function extractUtf16Strings(bytes, minLen = MIN_STRING_LEN) {
  // Windows PE binaries commonly embed UTF-16LE strings: char, 0x00, char, 0x00, ...
  const out = [];
  let chars = [];
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const lo = bytes[i];
    const hi = bytes[i + 1];
    if (hi === 0x00 && lo >= 0x20 && lo <= 0x7e) {
      chars.push(String.fromCharCode(lo));
    } else {
      if (chars.length >= minLen) out.push(chars.join(""));
      chars = [];
    }
  }
  if (chars.length >= minLen) out.push(chars.join(""));
  return out;
}

export async function extractStrings(file) {
  const buf = await file.slice(0, MAX_BYTES_SCANNED).arrayBuffer();
  const bytes = new Uint8Array(buf);
  const ascii = extractAsciiStrings(bytes);
  const utf16 = extractUtf16Strings(bytes);
  return { ascii, utf16, truncated: file.size > MAX_BYTES_SCANNED, bytes };
}

async function scanStringsAndSecrets(file) {
  const { ascii, utf16, truncated } = await extractStrings(file);
  const combined = [...ascii, ...utf16].join("\n");
  const { findings, verdict, riskScore } = scanSecrets(combined);
  return { stringCount: ascii.length + utf16.length, truncated, findings, verdict, riskScore };
}

function scoreManifest(permissions, severityMap) {
  const flagged = permissions
    .filter((p) => severityMap[p])
    .map((p) => ({ name: p, severity: severityMap[p] }));
  const highCount = flagged.filter((f) => f.severity === "high").length;
  const medCount = flagged.filter((f) => f.severity === "medium").length;
  const riskScore = Math.min(100, highCount * 25 + medCount * 10);
  const verdict = riskScore >= 70 ? "dangerous" : riskScore >= 30 ? "suspicious" : "safe";
  return { flagged, riskScore, verdict };
}

const IPA_INFO_PLIST_RE = /^Payload\/[^/]+\.app\/Info\.plist$/;

async function tryParsePackage(file) {
  const buf = await file.arrayBuffer();
  let entries;
  try {
    entries = listZipEntries(buf);
  } catch {
    return { isZip: false };
  }

  const manifestEntry = entries.get("AndroidManifest.xml");
  if (manifestEntry) {
    try {
      const manifestBytes = await extractZipEntry(buf, manifestEntry);
      const { package: pkg, permissions } = parseManifest(manifestBytes.buffer);
      return { isZip: true, platform: "android", entryCount: entries.size, package: pkg, permissions, severityMap: DANGEROUS_PERMISSIONS };
    } catch (err) {
      return { isZip: true, platform: null, entryCount: entries.size, manifestError: err.message };
    }
  }

  const plistName = [...entries.keys()].find((n) => IPA_INFO_PLIST_RE.test(n));
  if (plistName) {
    try {
      const plistBytes = await extractZipEntry(buf, entries.get(plistName));
      const plist = parsePlist(plistBytes.buffer);
      const permissions = Object.keys(plist || {}).filter((k) => k.endsWith("UsageDescription"));
      return {
        isZip: true,
        platform: "ios",
        entryCount: entries.size,
        package: plist?.CFBundleIdentifier || null,
        permissions,
        severityMap: DANGEROUS_USAGE_DESCRIPTIONS,
      };
    } catch (err) {
      return { isZip: true, platform: null, entryCount: entries.size, manifestError: err.message };
    }
  }

  return { isZip: true, platform: null, entryCount: entries.size };
}

function worseVerdict(a, b) {
  const rank = { safe: 0, suspicious: 1, dangerous: 2, unknown: 0 };
  return rank[b] > rank[a] ? b : a;
}

export async function checkApp(file) {
  const [strings, pkg] = await Promise.all([scanStringsAndSecrets(file), tryParsePackage(file)]);

  let manifestScore = { flagged: [], riskScore: 0, verdict: "safe" };
  if (pkg.platform && pkg.permissions) manifestScore = scoreManifest(pkg.permissions, pkg.severityMap);

  const verdict = worseVerdict(strings.verdict, manifestScore.verdict);
  const riskScore = Math.max(strings.riskScore, manifestScore.riskScore);

  const flagLabels = [
    ...strings.findings.map((f) => f.name),
    ...manifestScore.flagged.map((f) => `${pkg.platform === "ios" ? "Permiso (uso declarado)" : "Permiso peligroso"}: ${f.name}`),
  ];

  const result = {
    type: "app",
    input: file.name,
    size: file.size,
    isZip: pkg.isZip,
    platform: pkg.platform || null,
    package: pkg.package || null,
    permissions: pkg.permissions || [],
    dangerousPermissions: manifestScore.flagged,
    secretFindings: strings.findings,
    stringCount: strings.stringCount,
    truncated: strings.truncated,
    verdict,
    riskScore,
    timestamp: Date.now(),
  };

  await saveResult({
    type: "app",
    input: file.name,
    verdict,
    riskScore,
    flags: flagLabels,
    timestamp: result.timestamp,
    raw: result,
  });

  return result;
}
