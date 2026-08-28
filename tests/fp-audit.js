// Auditoría de falsos positivos: corpus de entradas LEGÍTIMAS reales.
// Nada de esto debería marcarse como peligroso. Imprime una tabla con lo que sí se marca,
// para revisarlo a mano — no es un test de pass/fail, es un informe.
import { checkUrl } from "../public/js/modules/urlModule.js";
import { checkSms } from "../public/js/modules/smsModule.js";
import { checkMail } from "../public/js/modules/mailModule.js";
import { checkFile } from "../public/js/modules/fileModule.js";
import { scanSecrets } from "../public/js/modules/secretsModule.js";
import { checkApp } from "../public/js/modules/appsModule.js";
import { decodeAll } from "../public/js/modules/decodeModule.js";

const rows = [];
function record(module, input, verdict, flags, note = "") {
  rows.push({ module, input, verdict, flags: flags.join(", "), note });
}

// crypto.getRandomValues tiene un límite de 64KB por llamada
function randomBytes(n) {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) {
    crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  }
  return out;
}

// ---------------- URLs legítimas ----------------
const BENIGN_URLS = [
  "https://abc.xyz",
  "https://github.com/anthropics/claude-code",
  "https://www.amazon.es/dp/B08N5WRWNW",
  "https://amazon.de/dp/B08N5WRWNW",
  "https://amazon.fr/dp/B08N5WRWNW",
  "https://amazon.it/dp/B08N5WRWNW",
  "https://es.wikipedia.org/wiki/Ciberseguridad",
  "https://sede.seg-social.gob.es/wps/portal/sede",
  "https://s3.eu-west-1.amazonaws.com/mi-bucket/archivo.pdf",
  "https://example.com/contacto?email=juan@example.com",
  "https://drive.google.com/file/d/1a2b3c/view",
  "https://mail.google.com/mail/u/0/#inbox",
  "https://open.spotify.com/track/abc123",
  "https://docs.google.com/document/d/xyz/edit",
  "https://www.bbva.es/personas.html",
  "https://linktr.ee/alguien",
  "https://example.com:8443/panel",
  "https://münchen.de",
  "https://mañana.es",
  "https://café.fr",
  "https://raw.githubusercontent.com/user/repo/main/README.md",
  "https://cdn.jsdelivr.net/npm/paquete@1.0.0/dist/index.js",
  "https://my-company-product-page.com",
  "https://correos.es/es/es/particulares",
  "https://www.google.es/maps",
  "https://x.com/usuario",
  "https://vercel.com",
  "https://fly.io",
  "https://bit.ly/3xxxxx",
  // segunda tanda
  "https://www.bbva.es",
  "https://www.santander.es/particulares",
  "https://www.boe.es/diario_boe/",
  "https://sede.administracion.gob.es/PAG_Sede/HomeSede.html",
  "https://www.agenciatributaria.gob.es/AEAT.sede",
  "https://d1a2b3c4d5e6f7.cloudfront.net/assets/app.js",
  "https://t.me/uncanal",
  "https://wa.me/34600000000",
  "https://youtu.be/dQw4w9WgXcQ",
  "https://www.instituto-nacional-estadistica.es/datos",
  "https://api.github.com/repos/anthropics/claude-code/issues?state=open",
  "https://es.stackoverflow.com/questions/12345/como-hacer-x",
  "https://www.renfe.com/es/es",
  "https://www.idealista.com/inmueble/12345678/",
];

// ---------------- SMS legítimos ----------------
const BENIGN_SMS = [
  "Tu codigo de verificacion es 847362. No lo compartas con nadie.",
  "Your verification code is 483920. Do not share it.",
  "BBVA: se ha realizado un cargo de 45,20 EUR en tu tarjeta terminada en 1234.",
  "Tu contraseña de Netflix se ha cambiado correctamente. Si no fuiste tu, contacta con soporte.",
  "Hola! Te confirmo la cena del viernes a las 21h",
  "Tu pedido de Amazon llega manana. Detalles en https://amazon.es/pedidos",
  "Correos: tu envio 1234 sale hoy a reparto. Sigue el envio en https://correos.es/seguimiento",
  "Cita confirmada en el centro de salud el 12/03 a las 10:15h",
  "Su cita con la DGT esta confirmada para el 14/05. Mas info en https://sede.dgt.gob.es",
  "Recuerda: manana es el ultimo dia para presentar la declaracion. Agencia Tributaria",
  "Oferta por tiempo limitado: 20% de descuento en tu proxima compra",
  "Has ganado 5 puntos en tu tarjeta de fidelidad del supermercado",
  "Uber: tu conductor llega en 3 minutos",
  "Tu paquete de DHL ha sido entregado en tu domicilio",
  // segunda tanda
  "Su pedido n. 12345 ha sido enviado y llegara el martes",
  "Codigo Amazon: 123456",
  "Banco Santander: Compra de 30,00 EUR en MERCADONA con tarjeta *1234",
  "Le recordamos su cita medica manana a las 10:00 en el centro de salud",
  "Su reserva esta confirmada. Ver detalles en https://booking.com/confirmacion",
  "Iberia: su vuelo IB3456 sale a las 14:20 por la puerta B12",
  "Verificacion en dos pasos activada correctamente en tu cuenta",
  "Tu pedido de Glovo llega en 10 minutos",
  "Correos: entrega prevista hoy. Seguimiento: https://s.correos.es/abc123",
  "Hemos recibido tu solicitud. Te avisaremos por email cuando este lista.",
  "Recuerda que manana vence el plazo de matriculacion en la universidad",
];

// ---------------- Correos legítimos ----------------
const BENIGN_MAILS = [
  {
    name: "boletin legitimo via ESP (Mailchimp)",
    raw:
      "From: Boletin Empresa <news@miempresa.com>\n" +
      "Return-Path: bounce-123@mail139.mailchimp.com\n" +
      "Reply-To: soporte@miempresa.com\n" +
      "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Hola! Aqui tienes nuestras novedades. Siguenos en Facebook e Instagram. Ver online: https://miempresa.com/boletin",
  },
  {
    name: "email personal simple",
    raw:
      "From: Ana <ana@example.com>\n" +
      "Return-Path: ana@example.com\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Te paso el documento que hablamos, un saludo",
  },
  {
    name: "notificacion real de Google",
    raw:
      "From: Google <no-reply@accounts.google.com>\n" +
      "Return-Path: no-reply@accounts.google.com\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Se ha iniciado sesion en tu cuenta de Google desde un dispositivo nuevo. Revisa la actividad en https://myaccount.google.com/security",
  },
  {
    name: "lista de correo (mailing list)",
    raw:
      "From: Desarrollador <dev@proyecto.org>\n" +
      "Return-Path: lista-bounces@listas.servidor.net\n" +
      "Reply-To: lista@listas.servidor.net\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Adjunto el parche que comentabamos en la reunion",
  },
  {
    name: "factura legitima con accion requerida",
    raw:
      "From: Facturacion <facturas@miproveedor.com>\n" +
      "Return-Path: facturas@miproveedor.com\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Accion requerida: revise su factura mensual en https://miproveedor.com/facturas",
  },
];

// ---------------- Código legítimo sin secretos ----------------
const BENIGN_CODE = [
  { name: "config con placeholders", text: 'api_key: "YOUR_API_KEY_HERE"\nsecret: "changeme"' },
  { name: "git sha y hashes", text: "commit 9f2f9721a3b4c5d6e7f8091a2b3c4d5e6f708192\nsha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { name: "codigo normal", text: "function suma(a, b) {\n  return a + b;\n}\nconst SKIP_VALIDATION = false;" },
  { name: "docs con ejemplo redactado", text: "Usa tu clave: sk-XXXXXXXXXXXXXXXXXXXX (sustituyela por la tuya)" },
  { name: "UUID y bases de datos", text: "id: 550e8400-e29b-41d4-a716-446655440000\nDATABASE_URL=postgres://localhost:5432/midb" },
  { name: "clave publica Stripe (es publica por diseno)", text: 'const stripe = Stripe("pk_live_51H8xAbCdEfGhIjKlMnOpQrStUvWx");' },
  // Nota: "SK" + 32 hex NO se prueba aquí como benigno porque ESE es literalmente el formato
  // de un SID de Twilio: marcarlo es correcto, no un falso positivo.
  { name: "codigos de producto y referencias", text: "Referencia SKU-99213, lote L2024-A, pedido n. 84213-ES" },
  { name: "cabeceras HTTP normales", text: "Content-Type: application/json\nAuthorization: Basic dXNlcjpwYXNz" },
  // segunda tanda
  { name: "package-lock con hashes de integridad", text: '"integrity": "sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ=="' },
  { name: "imagen embebida como data URI", text: 'background: url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")' },
  { name: "comentario mencionando password", text: "// TODO: mover la password de la base de datos a una variable de entorno" },
  { name: "fichero .env de ejemplo", text: "DB_HOST=localhost\nDB_PORT=5432\nAPI_KEY=\nSECRET=" },
  { name: "CSS minificado", text: ".a{color:#fff}.b{margin:0}.c{padding:1rem}.sk-spinner{animation:spin 1s linear infinite}" },
];

// ---------------- Correos legítimos, segunda tanda ----------------
const BENIGN_MAILS_2 = [
  {
    name: "marca en el nombre mostrado con dominio correcto",
    raw:
      "From: Amazon.es <no-reply@amazon.es>\n" +
      "Return-Path: bounce@amazon.es\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Tu pedido ha sido enviado. Sigue el envio en https://amazon.es/pedidos",
  },
  {
    name: "aviso oficial legitimo enlazando a su propio dominio",
    raw:
      "From: Agencia Tributaria <no-reply@agenciatributaria.gob.es>\n" +
      "Return-Path: no-reply@agenciatributaria.gob.es\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Tiene una notificacion pendiente. Consulte su informacion en https://sede.agenciatributaria.gob.es",
  },
  {
    name: "notificacion de GitHub",
    raw:
      "From: GitHub <notifications@github.com>\n" +
      "Return-Path: bounce@github.com\n" +
      "Reply-To: reply@reply.github.com\n" +
      "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\n" +
      "Nuevo comentario en tu issue: https://github.com/usuario/repo/issues/1",
  },
];

async function run() {
  // URLs
  for (const u of BENIGN_URLS) {
    try {
      const r = await checkUrl(u, { networkEnabled: false });
      if (r.verdict !== "safe") record("URL", u, r.verdict, r.flags);
    } catch (e) {
      record("URL", u, "ERROR", [], e.message);
    }
  }

  // SMS
  for (const s of BENIGN_SMS) {
    const r = await checkSms(s);
    if (r.verdict !== "safe") record("SMS", s.slice(0, 60) + "…", r.verdict, r.flags);
  }

  // Mail
  for (const m of [...BENIGN_MAILS, ...BENIGN_MAILS_2]) {
    const r = await checkMail(m.raw);
    if (r.verdict !== "safe") record("Correo", m.name, r.verdict, r.flags);
  }

  // Secrets
  for (const c of BENIGN_CODE) {
    const r = scanSecrets(c.text);
    if (r.findings.length > 0) record("Secretos", c.name, r.verdict, r.findings.map((f) => f.name));
  }

  // Files: instaladores legitimos comprimidos (alta entropia) y formatos comunes
  const random = randomBytes(300000);
  const installer = new Uint8Array([0x4d, 0x5a, ...random]);
  const rf = await checkFile(new File([installer], "instalador-legitimo.exe"));
  if (rf.verdict !== "safe") record("Archivos", "instalador .exe comprimido (entropia alta)", rf.verdict, rf.flags);

  const webp = new Uint8Array([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50, ...new Array(40).fill(0)]);
  const rw = await checkFile(new File([webp], "foto.webp"));
  record("Archivos", "foto.webp (formato comun)", rw.verdict, rw.flags, "detectado: " + rw.detected);

  // Apps: binario legitimo grande con datos aleatorios (simula .so/.dex comprimido)
  const bigRandom = randomBytes(2000000);
  const t0 = performance.now();
  const ra = await checkApp(new File([bigRandom], "libreria-legitima.so"));
  record("Apps", "tiempo de escaneo de 2MB", Math.round(performance.now() - t0) + " ms", [], "un APK real son 20-100MB");
  if (ra.verdict !== "safe") {
    record("Apps", "binario aleatorio 2MB (sin secretos reales)", ra.verdict, ra.secretFindings.map((f) => f.name));
  }

  // Decoder: texto plano normal no deberia "decodificarse" a basura
  for (const t of ["Hola mundo", "deadbeef", "test", "contraseña123"]) {
    const d = decodeAll(t);
    if (d.length > 0) record("Decodificador", t, "decodifica", d.map((x) => `${x.label}→${JSON.stringify(x.value.slice(0, 20))}`));
  }

  const el = document.getElementById("results");
  if (rows.length === 0) {
    el.innerHTML = "<p style='color:#34d399'>Ningún falso positivo detectado en el corpus.</p>";
  } else {
    el.innerHTML =
      `<p><strong>${rows.length} entradas legítimas marcadas (revisar):</strong></p>` +
      "<table border='1' cellpadding='6' style='border-collapse:collapse;font-size:13px'>" +
      "<tr><th>Módulo</th><th>Entrada</th><th>Veredicto</th><th>Flags</th><th>Nota</th></tr>" +
      rows
        .map(
          (r) =>
            `<tr><td>${esc(r.module)}</td><td>${esc(r.input)}</td><td style="color:#f87171">${esc(r.verdict)}</td><td>${esc(r.flags)}</td><td>${esc(r.note)}</td></tr>`
        )
        .join("") +
      "</table>";
  }
  console.log("FP audit rows:", JSON.stringify(rows, null, 2));
  window.__fpRows = rows;
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
}

run();
