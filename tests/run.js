import { test, assert, assertEqual, runAll } from "./harness.js";
import { buildTestJpeg, buildTestZip, buildTestAxml, buildTestBinaryPlist } from "./fixtures.js";

import { checkUrl, offlineUrlFlags } from "../public/js/modules/urlModule.js";
import { checkFile } from "../public/js/modules/fileModule.js";
import { checkMail } from "../public/js/modules/mailModule.js";
import { checkSms } from "../public/js/modules/smsModule.js";
import { decodeJwt } from "../public/js/modules/jwtModule.js";
import { estimatePassword } from "../public/js/modules/passwordModule.js";
import { decodeAll } from "../public/js/modules/decodeModule.js";
import { scanSecrets } from "../public/js/modules/secretsModule.js";
import { parseExif } from "../public/js/modules/exifModule.js";
import { checkApp } from "../public/js/modules/appsModule.js";
import { listZipEntries, extractZipEntry } from "../public/js/zipReader.js";
import { parseManifest } from "../public/js/axmlParser.js";
import { parseBinaryPlist } from "../public/js/plistParser.js";
import { saveResult, listResults, deleteResult } from "../public/js/db.js";

// ---- URL module ----
test("urlModule: typosquat + @ + no-https flagged, verdict escalates", async () => {
  const r = await checkUrl("http://goog1e.com@evil.com/reset", { networkEnabled: false });
  assert(r.flags.includes("at_symbol"), "expected at_symbol flag");
  assert(r.flags.includes("no_https"), "expected no_https flag");
  assert(r.verdict !== "safe", "expected non-safe verdict");
});

test("urlModule: clean https url on known domain is safe", async () => {
  const r = await checkUrl("https://github.com/anthropics", { networkEnabled: false });
  assertEqual(r.verdict, "safe", "expected safe verdict");
  assertEqual(r.flags.length, 0, "expected no flags");
});

test("urlModule: offlineUrlFlags helper works standalone", async () => {
  const { flags } = await offlineUrlFlags("http://192.168.1.1/login");
  assert(flags.includes("ip_literal"), "expected ip_literal flag");
});

// ---- File module ----
test("fileModule: real PDF is safe", async () => {
  const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x34, ...new Array(20).fill(0x41)]);
  const r = await checkFile(new File([bytes], "invoice.pdf"));
  assertEqual(r.detected, "PDF");
  assertEqual(r.verdict, "safe");
});

test("fileModule: PE renamed to .pdf is dangerous (executable_disguised)", async () => {
  const bytes = new Uint8Array([0x4d, 0x5a, ...new Array(30).fill(0)]);
  const r = await checkFile(new File([bytes], "invoice.pdf"));
  assert(r.flags.includes("executable_disguised"));
  assertEqual(r.verdict, "dangerous");
});

test("fileModule: high-entropy executable flagged as packed", async () => {
  const random = new Uint8Array(2000);
  crypto.getRandomValues(random);
  const bytes = new Uint8Array([0x4d, 0x5a, ...random]);
  const r = await checkFile(new File([bytes], "packed.exe"));
  assert(r.flags.includes("high_entropy_executable"));
});

test("fileModule: real .doc (OLE/CFB) is safe", async () => {
  const bytes = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...new Array(20).fill(0)]);
  const r = await checkFile(new File([bytes], "informe.doc"));
  assertEqual(r.detected, "OLE/CFB (Office antiguo: doc/xls/ppt, o instalador MSI)");
  assertEqual(r.verdict, "safe");
});

test("fileModule: MSI (OLE/CFB) renamed to .pdf is dangerous", async () => {
  // Regression: MSI installers use the OLE/CFB container (D0 CF 11 E0), not PE — before this
  // fix magicBytes.js had no OLE signature at all and a renamed malicious .msi fell through
  // to "unknown" with no flag.
  const bytes = new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, ...new Array(20).fill(0)]);
  const r = await checkFile(new File([bytes], "factura.pdf"));
  assert(r.flags.includes("executable_disguised"));
  assertEqual(r.verdict, "dangerous");
});

// ---- Mail module ----
test("mailModule: spoofed brand + failed auth is dangerous", async () => {
  const r = await checkMail(
    'From: "PayPal Support" <security@paypa1-verify.ru>\nReturn-Path: bounce@other.com\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\nbody'
  );
  assert(r.flags.includes("display_name_spoof"));
  assert(r.flags.includes("spf_fail"));
  assertEqual(r.verdict, "dangerous");
});

test("mailModule: clean aligned headers is safe", async () => {
  const r = await checkMail(
    "From: Alice <alice@example.com>\nReturn-Path: alice@example.com\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nhi"
  );
  assertEqual(r.verdict, "safe");
});

test("mailModule: clean headers but body impersonates a brand with mismatched link is dangerous", async () => {
  // Regression: mailModule used to only look at headers, never the body — a compromised-but-
  // legitimate-looking sender with a phishing link in the body slipped through entirely.
  const r = await checkMail(
    "From: Notificaciones <no-reply@mailer-service.net>\nReturn-Path: no-reply@mailer-service.net\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Seg Social: tiene un tramite pendiente, consulte su informacion en https://portatsegsvcial.cfd/es"
  );
  assert(r.flags.includes("official_notice_language"), "expected official_notice_language flag");
  assert(r.flags.includes("brand_domain_mismatch"), "expected brand_domain_mismatch flag");
  assertEqual(r.verdict, "dangerous");
});

// ---- SMS module ----
test("smsModule: smishing text with shortened link is dangerous", async () => {
  const r = await checkSms("URGENTE tu paquete esta retenido en aduana, paga aqui http://bit.ly/abc");
  assert(r.flags.includes("urgency_language"));
  assert(r.flags.includes("shortened_url"));
  assertEqual(r.verdict, "dangerous");
});

test("smsModule: gov-impersonation smishing with abused TLD and brand/domain mismatch is dangerous", async () => {
  // Regression: a real message a user reported as a false negative — bureaucratic tone
  // ("tramite pendiente"), no urgency/lure keywords, no IP/at-symbol/typosquat, so it slipped
  // through until suspicious_tld + brand_domain_mismatch + official_notice_language were added.
  const r = await checkSms(
    "Seg Social: Tiene una actualizacion pendiente. Consulte su informacion y gestione el tramite pendiente. https://portatsegsvcial.cfd/es"
  );
  assert(r.flags.includes("official_notice_language"), "expected official_notice_language flag");
  assert(r.flags.includes("brand_domain_mismatch"), "expected brand_domain_mismatch flag");
  assert(r.flags.includes("suspicious_tld"), "expected suspicious_tld flag");
  assertEqual(r.verdict, "dangerous");
});

test("smsModule: brand mention with matching real domain does not false-positive", async () => {
  const r = await checkSms("Tu paquete de Correos esta en camino, sigue el envio en https://correos.es/seguimiento");
  assert(!r.flags.includes("brand_domain_mismatch"), "should not flag matching domain as mismatch");
  assert(!r.flags.includes("suspicious_tld"), "should not flag .es as suspicious");
});

test("smsModule: benign text is safe", async () => {
  const r = await checkSms("Nos vemos a las 8 en el bar de siempre?");
  assertEqual(r.verdict, "safe");
});

// ---- JWT ----
test("jwtModule: alg:none + expired token flagged", () => {
  const b64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const token = b64url({ alg: "none" }) + "." + b64url({ exp: Math.floor(Date.now() / 1000) - 100 }) + ".";
  const { flags } = decodeJwt(token);
  assert(flags.includes("alg_none"));
  assert(flags.includes("expired"));
});

test("jwtModule: valid future token has no flags", () => {
  const b64url = (obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const token = b64url({ alg: "HS256" }) + "." + b64url({ exp: Math.floor(Date.now() / 1000) + 3600 }) + ".sig";
  const { flags } = decodeJwt(token);
  assertEqual(flags.length, 0);
});

// ---- Password ----
test("passwordModule: common password scores near zero", () => {
  const r = estimatePassword("123456");
  assert(r.flags.includes("common_password"));
  assertEqual(r.category, "muy débil");
});

test("passwordModule: long random password scores strong", () => {
  const r = estimatePassword("Xk9#mQ2$vL7pR!4z");
  assert(r.entropy > 80, "expected high entropy");
});

// ---- Decode ----
test("decodeModule: base64 decodes to plain text", () => {
  const results = decodeAll("SGVsbG8gbXVuZG8=");
  const hit = results.find((r) => r.label === "Base64");
  assertEqual(hit.value, "Hello mundo");
});

// ---- Secrets ----
test("secretsModule: AWS key and private key block detected", () => {
  const r = scanSecrets('const AWS_KEY = "AKIAABCDEFGHIJKLMNOP";\n-----BEGIN RSA PRIVATE KEY-----');
  assertEqual(r.verdict, "dangerous");
  assert(r.findings.some((f) => f.name === "AWS Access Key ID"));
  assert(r.findings.some((f) => f.name === "Private key block"));
});

test("secretsModule: clean code has no findings", () => {
  const r = scanSecrets("function add(a, b) { return a + b; }");
  assertEqual(r.findings.length, 0);
  assertEqual(r.verdict, "safe");
});

test("secretsModule: OpenAI and Anthropic keys detected distinctly", () => {
  const r = scanSecrets(
    'const OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456";\nconst CLAUDE_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";'
  );
  assert(r.findings.some((f) => f.name === "OpenAI API key"), "expected OpenAI API key finding");
  assert(r.findings.some((f) => f.name === "Anthropic API key"), "expected Anthropic API key finding");
  assertEqual(r.verdict, "dangerous");
});

// ---- EXIF ----
test("exifModule: synthetic JPEG round-trips Make/Model/GPS", () => {
  const exif = parseExif(buildTestJpeg());
  assert(exif.hasExif);
  assertEqual(exif.make, "ACME");
  assertEqual(exif.model, "X1");
  assert(Math.abs(exif.gps.lat - 40.4346) < 0.001, "latitude mismatch");
  assert(Math.abs(exif.gps.lon - -3.7) < 0.001, "longitude mismatch");
});

// ---- ZIP reader ----
test("zipReader: stored and deflate entries round-trip", async () => {
  const zip = await buildTestZip([
    { name: "hello.txt", data: new TextEncoder().encode("Hello stored"), method: 0 },
    { name: "compressed.txt", data: new TextEncoder().encode("Hello compressed world, repeated text repeated text"), method: 8 },
  ]);
  const entries = listZipEntries(zip.buffer);
  assertEqual(entries.size, 2);
  const stored = await extractZipEntry(zip.buffer, entries.get("hello.txt"));
  const deflated = await extractZipEntry(zip.buffer, entries.get("compressed.txt"));
  assertEqual(new TextDecoder().decode(stored), "Hello stored");
  assertEqual(new TextDecoder().decode(deflated), "Hello compressed world, repeated text repeated text");
});

// ---- AXML parser ----
test("axmlParser: package and permissions extracted", () => {
  const axml = buildTestAxml("com.example.evil", ["android.permission.READ_SMS", "android.permission.INTERNET"]);
  const { package: pkg, permissions } = parseManifest(axml.buffer);
  assertEqual(pkg, "com.example.evil");
  assert(permissions.includes("android.permission.READ_SMS"));
  assert(permissions.includes("android.permission.INTERNET"));
});

// ---- plist parser ----
test("plistParser: binary plist round-trips string dict", () => {
  const bytes = buildTestBinaryPlist({ CFBundleIdentifier: "com.example.evilapp", NSCameraUsageDescription: "need camera" });
  const dict = parseBinaryPlist(bytes.buffer);
  assertEqual(dict.CFBundleIdentifier, "com.example.evilapp");
  assertEqual(dict.NSCameraUsageDescription, "need camera");
});

// ---- Apps module: IPA pipeline ----
test("appsModule: IPA with dangerous usage-description + embedded secret is dangerous", async () => {
  const plist = buildTestBinaryPlist({
    CFBundleIdentifier: "com.evil.iosspy",
    NSMicrophoneUsageDescription: "listens always",
    NSContactsUsageDescription: "reads contacts",
  });
  const binary = new TextEncoder().encode("filler AKIAABCDEFGHIJKLMNOP more filler bytes here padding");
  const zip = await buildTestZip([
    { name: "Payload/EvilApp.app/Info.plist", data: plist, method: 0 },
    { name: "Payload/EvilApp.app/EvilApp", data: binary, method: 0 },
  ]);
  const r = await checkApp(new File([zip], "evil.ipa"));
  assertEqual(r.platform, "ios");
  assertEqual(r.package, "com.evil.iosspy");
  assert(r.dangerousPermissions.some((p) => p.name === "NSMicrophoneUsageDescription"));
  assert(r.secretFindings.some((f) => f.name === "AWS Access Key ID"));
  assertEqual(r.verdict, "dangerous");
});

// ---- Apps module (full pipeline) ----
test("appsModule: APK with dangerous permission + embedded secret is dangerous", async () => {
  const axml = buildTestAxml("com.evil.spyware", ["android.permission.READ_SMS", "android.permission.CAMERA"]);
  const dex = new TextEncoder().encode("filler ghp_1234567890abcdefghijklmnopqrstuvwxyz12 filler");
  const zip = await buildTestZip([
    { name: "AndroidManifest.xml", data: axml, method: 0 },
    { name: "classes.dex", data: dex, method: 0 },
  ]);
  const r = await checkApp(new File([zip], "spyware.apk"));
  assertEqual(r.platform, "android");
  assertEqual(r.package, "com.evil.spyware");
  assert(r.dangerousPermissions.some((p) => p.name.includes("READ_SMS")));
  assert(r.secretFindings.some((f) => f.name === "GitHub token"));
  assertEqual(r.verdict, "dangerous");
});

test("appsModule: notification-listener and query-all-packages permissions flagged as dangerous", async () => {
  // Regression: these two are classic stalkerware/spyware indicators (read every notification,
  // enumerate every installed app) and were missing from the dangerous-permissions list.
  const axml = buildTestAxml("com.evil.stalkerware", [
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
  ]);
  const zip = await buildTestZip([{ name: "AndroidManifest.xml", data: axml, method: 0 }]);
  const r = await checkApp(new File([zip], "stalkerware.apk"));
  assert(r.dangerousPermissions.some((p) => p.name.includes("BIND_NOTIFICATION_LISTENER_SERVICE")));
  assert(r.dangerousPermissions.some((p) => p.name.includes("QUERY_ALL_PACKAGES")));
  assert(r.dangerousPermissions.every((p) => p.severity === "high"));
  assertEqual(r.verdict, "suspicious"); // 2 high-severity perms = 50 risk, below the 70 "dangerous" cutoff
});

test("appsModule: non-zip binary falls back to strings-only scan", async () => {
  const bytes = new TextEncoder().encode("plain exe filler AKIAABCDEFGHIJKLMNOP more filler bytes here");
  const r = await checkApp(new File([bytes], "tool.exe"));
  assertEqual(r.isZip, false);
  assert(r.secretFindings.some((f) => f.name === "AWS Access Key ID"));
});

// ---- db.js (IndexedDB / localStorage fallback) ----
test("db: save, list, delete round-trip", async () => {
  const saved = await saveResult({ type: "url", input: "https://test.example", verdict: "safe", riskScore: 0, flags: [] });
  const all = await listResults();
  assert(all.some((r) => r.id === saved.id), "saved record not found in listResults");
  await deleteResult(saved.id);
  const afterDelete = await listResults();
  assert(!afterDelete.some((r) => r.id === saved.id), "record still present after delete");
});

const resultsEl = document.getElementById("results");
const summary = await runAll(resultsEl);
window.__testSummary = summary;
