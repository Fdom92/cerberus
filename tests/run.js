import { test, assert, assertEqual, runAll } from "./harness.js";
import { buildTestJpeg, buildTestZip, buildTestAxml, buildTestBinaryPlist } from "./fixtures.js";

import { checkUrl, offlineUrlFlags, shortenerPreviewUrl } from "../public/js/modules/urlModule.js";
import { checkFile } from "../public/js/modules/fileModule.js";
import { checkMail } from "../public/js/modules/mailModule.js";
import { checkSms } from "../public/js/modules/smsModule.js";
import { decodeJwt } from "../public/js/modules/jwtModule.js";
import { estimatePassword } from "../public/js/modules/passwordModule.js";
import { decodeAll } from "../public/js/modules/decodeModule.js";
import { scanSecrets } from "../public/js/modules/secretsModule.js";
import { parseExif } from "../public/js/modules/exifModule.js";
import { checkApp } from "../public/js/modules/appsModule.js";
import { classifyQrPayload, checkQr } from "../public/js/modules/qrModule.js";
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

// --- Falsos positivos corregidos (ver docs/superpowers/specs) ---

test("urlModule: dominios con tilde/diéresis legítimos no son homógrafos", async () => {
  // URL.hostname devuelve punycode, así que la comprobación antigua (/[^\x00-\x7F]/ o "xn--")
  // marcaba como ataque cualquier dominio internacionalizado legítimo — mañana.es incluido.
  for (const u of ["https://mañana.es", "https://münchen.de", "https://café.fr"]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(!r.flags.includes("homograph"), `${u} no debería marcarse como homógrafo`);
    assertEqual(r.verdict, "safe");
  }
});

test("urlModule: homógrafo real (mezcla de alfabetos y sosias latino) sí se detecta", async () => {
  const mixto = await checkUrl("https://xn--pple-43d.com", { networkEnabled: false }); // аpple.com
  assert(mixto.flags.includes("homograph"), "mezcla latino+cirílico debería marcarse");
  const puro = await checkUrl("https://xn--80ak6aa92e.com", { networkEnabled: false }); // аррӏе.com
  assert(puro.flags.includes("homograph"), "cirílico que imita 'apple' debería marcarse");
});

test("urlModule: '@' en la ruta o la query no es el '@' peligroso", async () => {
  // Solo el userinfo (https://usuario@host) oculta el host real. Un email de contacto en la
  // query o un paquete npm con @version son completamente normales.
  for (const u of [
    "https://example.com/contacto?email=juan@example.com",
    "https://cdn.jsdelivr.net/npm/paquete@1.0.0/dist/index.js",
  ]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(!r.flags.includes("at_symbol"), `${u} no debería marcar at_symbol`);
  }
  const real = await checkUrl("https://google.com@evil.example/login", { networkEnabled: false });
  assert(real.flags.includes("at_symbol"), "el userinfo real sí debe marcarse");
});

// --- Evasiones cerradas (ver tests/evasion-audit.html) ---

test("urlModule: marca como subdominio del atacante se detecta", async () => {
  // paypal.com.inicio-sesion.net: el dominio real es del atacante y la marca va de subdominio.
  // Es la forma de dominio de phishing más común y antes pasaba completamente limpia.
  for (const u of ["https://paypal.com.inicio-sesion.net/login", "https://login.secure.paypal.com.verify.io/"]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(r.flags.includes("brand_subdomain_spoof"), `debería detectarse: ${u}`);
  }
});

test("urlModule: nombre de marca dentro de un dominio ajeno se detecta", async () => {
  for (const u of ["https://paypal-secure-login.com/verify", "https://bbva-clientes-acceso.com/login"]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(r.flags.includes("brand_in_hostname"), `debería detectarse: ${u}`);
  }
});

test("urlModule: dominios internacionales legítimos de una marca no son suplantación", async () => {
  // amazon.de/.fr y los subdominios de un dominio conocido comparten primera etiqueta con la
  // marca: son legítimos. Este test protege la restauración de typosquat a distancia 2.
  for (const u of ["https://amazon.de/dp/X", "https://amazon.fr/dp/X", "https://s.correos.es/abc"]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(!r.flags.includes("typosquat"), `no debería marcarse: ${u}`);
    assert(!r.flags.includes("brand_in_hostname"), `no debería marcarse: ${u}`);
  }
});

test("urlModule: typosquat a distancia 2 se vuelve a detectar", async () => {
  const r = await checkUrl("https://payypall.com/login", { networkEnabled: false });
  assert(r.flags.includes("typosquat"));
});

test("smsModule: caracteres invisibles y homoglifos no evaden las palabras clave", async () => {
  const zwsp = await checkSms("Verifica tu cu​enta en https://acceso-bbva.top/login");
  assert(zwsp.flags.includes("credential_request"), "el carácter de ancho cero no debe evadir");
  const cyr = await checkSms("Verifiсa tu cuenta en https://bbva-seguro.top/login");
  assert(cyr.flags.includes("credential_request"), "el homoglifo cirílico no debe evadir");
});

test("smsModule: estafa telefónica sin enlace se detecta", async () => {
  const r = await checkSms("Su cuenta ha sido bloqueada. Llame al 900 123 456 para reactivarla.");
  assert(r.flags.includes("callback_number"));
  assertEqual(r.verdict, "suspicious");
});

test("mailModule: la marca suplantada en el Subject cuenta como identidad", async () => {
  const r = await checkMail(
    "From: Servicio <aviso@correo-notificacion.net>\nSubject: Su cuenta de PayPal ha sido suspendida\n" +
      "Return-Path: aviso@correo-notificacion.net\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Acceda para restablecerla: https://paypal-restablecer.top/login"
  );
  assert(r.flags.includes("display_name_spoof"), "el asunto debe contar para la suplantación");
  assertEqual(r.verdict, "dangerous");
});

test("fileModule: doble extensión se detecta aunque el contenido coincida con la extensión final", async () => {
  // factura.pdf.exe es un .exe de verdad, así que no hay discrepancia de firma: lo que
  // delata al fichero es el nombre, que aparenta ser un documento.
  const bytes = new Uint8Array([0x4d, 0x5a, ...new Array(40).fill(0)]);
  for (const name of ["factura.pdf.exe", "nomina.pdf     .exe"]) {
    const r = await checkFile(new File([bytes], name));
    assert(r.flags.includes("double_extension"), `debería detectarse: ${name}`);
    assertEqual(r.verdict, "dangerous");
  }
});

test("secretsModule: una clave real no se descarta por contener 'YOUR'", () => {
  const r = scanSecrets('aws_key = "AKIAYOURJ7SHDN2P4KQ1"');
  assert(r.findings.some((f) => f.name === "AWS Access Key ID"));
});

test("secretsModule: clave escondida en base64 se detecta", () => {
  const r = scanSecrets('const k = atob("QUtJQUlPU0ZPRE5ON1JFQUxLRVk5OQ==");');
  assert(r.findings.some((f) => f.name.includes("base64")));
});

// --- Campañas reales (ver tests/campaign-audit.html) ---

test("smsModule: estafa del 'hijo en apuros' se detecta sin enlace ni marca", async () => {
  const r = await checkSms("Hola mama, se me ha roto el movil y este es mi numero nuevo. Necesito que me hagas un pago urgente.");
  assert(r.flags.includes("family_impersonation"));
  assert(r.verdict !== "safe");
});

test("smsModule: marcas españolas frecuentes en phishing se reconocen", async () => {
  for (const [texto, marca] of [
    ["Has recibido un Bizum de 50 EUR. Acepta en https://bizum-cobros.top/aceptar", "Bizum"],
    ["ENDESA: factura impagada, abone en https://endesa-pagos.icu/factura", "Endesa"],
  ]) {
    const r = await checkSms(texto);
    assertEqual(r.verdict, "dangerous", `debería detectarse la suplantación de ${marca}`);
  }
});

test("mailModule: el asunto entra en las heurísticas de texto (fraude del CEO)", async () => {
  const r = await checkMail(
    "From: Direccion <direccion@empresa-nomina.info>\nSubject: Accion requerida: actualizacion de datos bancarios\n" +
      "Return-Path: direccion@empresa-nomina.info\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Necesitamos que actualice sus datos bancarios en https://empresa-nomina.info/rrhh"
  );
  assert(r.flags.includes("official_notice_language"), "'Accion requerida' va en el asunto");
  assert(r.flags.includes("credential_request"));
  assert(r.verdict !== "safe");
});

test("urlModule: enlace directo a un ejecutable se marca", async () => {
  const r = await checkUrl("https://grupo-suministros.info/factura.pdf.exe", { networkEnabled: false });
  assert(r.flags.includes("executable_link"));
});

test("urlModule: rutas web normales no se confunden con ejecutables", async () => {
  // .js lo carga toda web, y una query que acaba en un correo termina en ".com"
  for (const u of ["https://cdn.jsdelivr.net/npm/x/dist/index.js", "https://example.com/c?email=juan@example.com"]) {
    const r = await checkUrl(u, { networkEnabled: false });
    assert(!r.flags.includes("executable_link"), `no debería marcarse: ${u}`);
  }
});

test("urlModule: homógrafo con tilde de una marca conocida (córreos.es)", async () => {
  const r = await checkUrl("https://xn--crreos-bxa.es/envio", { networkEnabled: false });
  assert(r.flags.includes("homograph"), "sin tildes es exactamente correos.es");
});

test("urlModule: los acortadores ofrecen vista previa oficial", () => {
  assert(shortenerPreviewUrl("https://bit.ly/abc") === "https://bit.ly/abc+");
  assert(shortenerPreviewUrl("https://tinyurl.com/abc").startsWith("https://preview.tinyurl.com/"));
  assertEqual(shortenerPreviewUrl("https://example.com/abc"), null);
});

test("fileModule: ejecutable dentro de un ZIP se detecta", async () => {
  const u16 = (n) => [n & 0xff, (n >> 8) & 0xff];
  const u32 = (n) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
  const name = new TextEncoder().encode("Presupuesto.pdf.exe");
  const data = new Uint8Array([0x4d, 0x5a, ...new Array(50).fill(0)]);
  const local = [...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(data.length), ...u32(data.length), ...u16(name.length), ...u16(0), ...name, ...data];
  const central = [...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(data.length), ...u32(data.length), ...u16(name.length),
    ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(0), ...name];
  const eocd = [...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(1), ...u16(1),
    ...u32(central.length), ...u32(local.length), ...u16(0)];
  const zip = new Uint8Array([...local, ...central, ...eocd]);
  const r = await checkFile(new File([zip], "Presupuesto.zip"));
  assert(r.flags.includes("archive_contains_executable"));
  assertEqual(r.verdict, "dangerous");
});

test("urlModule: un TLD abusado por sí solo no basta para sospechar", async () => {
  const r = await checkUrl("https://abc.xyz", { networkEnabled: false }); // dominio de Alphabet
  assert(r.flags.includes("suspicious_tld"), "el TLD se sigue señalando");
  assertEqual(r.verdict, "safe"); // pero no alcanza el umbral en solitario
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

test("fileModule: high-entropy executable reported as packed but NOT dangerous on its own", async () => {
  // Casi todo instalador legítimo va comprimido: la entropía alta se informa, pero marcar
  // "dangerous" por eso sola convertía cualquier instalador descargado en un falso positivo.
  const random = new Uint8Array(2000);
  crypto.getRandomValues(random);
  const bytes = new Uint8Array([0x4d, 0x5a, ...random]);
  const r = await checkFile(new File([bytes], "packed.exe"));
  assert(r.flags.includes("packed_executable"));
  assertEqual(r.verdict, "safe");
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

test("mailModule: boletín legítimo enviado por un ESP no se marca", async () => {
  // Return-Path del proveedor de envío y Reply-To distinto son el comportamiento NORMAL de
  // Mailchimp/SendGrid y de cualquier lista de correo; mencionar "Facebook" no es suplantarlo.
  const r = await checkMail(
    "From: Boletin Empresa <news@miempresa.com>\n" +
      "Return-Path: bounce-123@mail139.mailchimp.com\n" +
      "Reply-To: soporte@miempresa.com\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Hola! Siguenos en Facebook e Instagram. Ver online: https://miempresa.com/boletin"
  );
  assert(!r.flags.includes("brand_domain_mismatch"), "mencionar una marca no es suplantarla");
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

test("smsModule: los SMS de código 2FA legítimos NO se marcan", async () => {
  // Es el SMS legítimo más frecuente que existe. La lista antigua incluía "codigo de
  // verificacion" y "contraseña" a secas, así que marcaba sospechoso medio buzón de la gente.
  for (const s of [
    "Tu codigo de verificacion es 847362. No lo compartas con nadie.",
    "Your verification code is 483920. Do not share it.",
    "Tu contraseña de Netflix se ha cambiado correctamente.",
  ]) {
    const r = await checkSms(s);
    assert(!r.flags.includes("credential_request"), `no debería marcar: ${s}`);
    assertEqual(r.verdict, "safe");
  }
});

test("smsModule: pedir que introduzcas credenciales sí se marca", async () => {
  const r = await checkSms("Su cuenta esta bloqueada. Introduce tu contraseña en https://verificar-cuenta.top/login");
  assert(r.flags.includes("credential_request"), "una petición real de credenciales debe marcarse");
});

test("smsModule: enlace legítimo del dominio .gob.es de la administración no es suplantación", async () => {
  const r = await checkSms("Su cita con la DGT esta confirmada para el 14/05. Mas info en https://sede.dgt.gob.es");
  assert(!r.flags.includes("brand_domain_mismatch"), "sede.dgt.gob.es es el dominio real de la DGT");
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

test("secretsModule: los placeholders de documentación no se marcan como claves reales", () => {
  const r = scanSecrets(
    'const OPENAI_KEY = "sk-XXXXXXXXXXXXXXXXXXXXXXXX";\napi_key: "YOUR_API_KEY_HERE"\ntoken: "<tu-token-aqui>"'
  );
  assertEqual(r.findings.length, 0);
  assertEqual(r.verdict, "safe");
});

test("secretsModule: la clave publicable de Stripe no se trata como secreto", () => {
  // pk_live_ está diseñada para ir en el JS público del checkout: avisar de ella era incorrecto.
  const r = scanSecrets('const stripe = Stripe("pk_live_51H8xAbCdEfGhIjKlMnOpQrStUvWx");');
  assertEqual(r.findings.length, 0);
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


// ---- qrModule ----
// Un QR no se puede leer a ojo, así que lo que importa es que el contenido salga clasificado
// tal cual es ANTES de que el móvil actúe sobre él.
test("qrModule: un QR con URL hereda todo el análisis de enlaces", async () => {
  const r = await checkQr("https://pago-multa-dgt.top/abonar", { networkEnabled: false, persist: false });
  assertEqual(r.kind, "url");
  assert(r.nested.flags.includes("brand_in_hostname"));
  assertEqual(r.verdict, "suspicious");
});

test("qrModule: URL sin esquema (como la escriben casi todos los QR) se reconoce igual", () => {
  const c = classifyQrPayload("bbva-clientes.top/acceso");
  assertEqual(c.kind, "url");
  assertEqual(c.urlNormalizada, "https://bbva-clientes.top/acceso");
});

test("qrModule: otpauth se marca — es el QR que enlaza tu 2FA con otra persona", () => {
  const c = classifyQrPayload("otpauth://totp/BBVA:fer?secret=JBSWY3DPEHPK3PXP&issuer=BBVA");
  assertEqual(c.kind, "otpauth");
  assert(c.flags.includes("qr_otpauth"));
});

test("qrModule: wifi abierta se distingue de wifi con contraseña", () => {
  assert(classifyQrPayload("WIFI:T:nopass;S:Free_WiFi;;").flags.includes("qr_wifi_open"));
  const conClave = classifyQrPayload("WIFI:T:WPA;S:MiCasa;P:secreta123;;");
  assert(!conClave.flags.includes("qr_wifi_open"));
  assertEqual(conClave.detalle, "MiCasa");
});

test("qrModule: número de tarificación especial y SMS preescrito se detectan", () => {
  assert(classifyQrPayload("tel:+34905123456").flags.includes("qr_premium_number"));
  const sms = classifyQrPayload("SMSTO:80345:ALTA");
  assert(sms.flags.includes("qr_premium_number"));
  assert(sms.flags.includes("qr_sms_preescrito"));
});

test("qrModule: javascript: y data: no son enlaces, son ejecución", () => {
  assert(classifyQrPayload("javascript:fetch('//evil.tld')").flags.includes("qr_javascript"));
  assert(classifyQrPayload("data:text/html;base64,PHNjcmlwdD4=").flags.includes("qr_data_uri"));
});

test("qrModule: un QR corriente no dispara nada", async () => {
  const menu = await checkQr("https://www.google.com/maps", { networkEnabled: false, persist: false });
  assertEqual(menu.verdict, "safe");
  const tel = classifyQrPayload("tel:+34911234567");
  assertEqual(tel.flags.length, 0);
  assertEqual(classifyQrPayload("Mesa 4 - pide por aqui").kind, "texto");
});

// ---- edad de dominio ----
// La consulta RDAP iba con el hostname completo, y RDAP solo entiende el dominio registrable:
// "www.loquesea.com" devolvía 404 y la señal más fuerte que tiene la app no llegaba a
// aplicarse nunca en ninguna URL con subdominio, o sea en casi ninguna.
test("urlModule: los dominios de marca entran en la comparación de typosquatting", async () => {
  const r = await checkUrl("https://bbvaa.es/acceso", { networkEnabled: false, persist: false });
  assert(r.flags.includes("typosquat"), "typosquat de un banco español no detectado");
  const legitimo = await checkUrl("https://bbva.es", { networkEnabled: false, persist: false });
  assertEqual(legitimo.flags.length, 0);
});

test("urlModule: checkUrl acepta persist:false y no escribe en el historial", async () => {
  const antes = (await listResults()).length;
  await checkUrl("https://example.com", { networkEnabled: false, persist: false });
  assertEqual((await listResults()).length, antes);
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
