// Red team final: campañas de phishing REALES y completas, tal y como llegan en España,
// no evasiones sintéticas de heurísticas sueltas.
//
// Se prueba en el estado POR DEFECTO (red apagada), porque es como la va a tener la mayoría.
// Lo que salga "safe" sin red y sin aviso útil es un fallo real de cobertura.
import { checkSms } from "../public/js/modules/smsModule.js";
import { checkMail } from "../public/js/modules/mailModule.js";
import { checkUrl } from "../public/js/modules/urlModule.js";
import { checkFile } from "../public/js/modules/fileModule.js";

const rows = [];
function rec(cat, nombre, verdict, score, flags) {
  rows.push({ cat, nombre, verdict, score, flags: (flags || []).join(", ") || "—" });
}

// ---------------- Smishing real en España ----------------
const CAMPANAS_SMS = [
  ["Correos: tasa de aduana", "CORREOS: Su paquete con referencia ES4521 no pudo entregarse por tasas aduaneras pendientes de 1,79 EUR. Regularice su envio en: https://correos-tasas.info/pago"],
  ["BBVA: cuenta suspendida", "Su cuenta BBVA ha sido suspendida temporalmente por seguridad. Acceda para reactivarla: https://bbva.movil-acceso.com/login"],
  ["Santander: cargo no reconocido", "Santander: Se ha detectado un cargo de 480,00 EUR no reconocido. Si no lo reconoce cancele aqui: https://santander-segura.info/cancelar"],
  ["CaixaBank: tarjeta bloqueada", "CaixaBank informa: su tarjeta ha sido bloqueada. Desbloquee en https://caixa-clientes.top/desbloqueo"],
  ["DGT: multa pendiente", "DGT: Consta una sancion pendiente de 90 EUR a su nombre. Consulte el expediente: https://dgt-multas.sbs/expediente"],
  ["Agencia Tributaria: devolución", "Agencia Tributaria: le corresponde una devolucion de 327,45 EUR. Solicitela antes del 30/11: https://aeat-devoluciones.cfd/solicitud"],
  ["Seg. Social: prestación", "Seguridad Social: tiene una prestacion pendiente de tramitar. Acceda con su certificado: https://sedeseg-social.online/tramite"],
  ["Bizum recibido (falso)", "Has recibido un Bizum de 50,00 EUR. Acepta el cobro en el siguiente enlace: https://bizum-cobros.top/aceptar"],
  ["Endesa: factura impagada", "ENDESA: Su factura de 87,32 EUR esta impagada. Evite el corte de suministro abonandola en https://endesa-pagos.icu/factura"],
  ["Netflix: pago rechazado", "Netflix: no hemos podido procesar tu pago. Actualiza tu metodo de pago en https://netflix-pagos.cyou/actualizar"],
  ["Amazon: entrega fallida", "Amazon: no pudimos entregar tu pedido. Reprograma la entrega aqui: https://amazon-entregas.click/reprogramar"],
  ["Movistar: puntos a canjear", "Movistar: tiene 3200 puntos a punto de caducar. Canjeelos ahora en https://movistar-puntos.rest/canjear"],
  ["Hijo en apuros (sin enlace)", "Hola mama, se me ha roto el movil y este es mi numero nuevo. Escribeme por WhatsApp cuando puedas, necesito que me hagas un pago urgente."],
  ["Soporte falso (llamada)", "AVISO: Se ha detectado actividad sospechosa en su cuenta bancaria. Contacte urgentemente con nuestro departamento de seguridad en el 912 345 678."],
];

// ---------------- Correo: phishing moderno (SPF/DKIM PASAN) ----------------
// Clave: el atacante tiene su propio dominio y lo configura bien, así que la autenticación
// pasa. Confiar en SPF/DKIM ya no distingue nada por sí solo.
const CAMPANAS_MAIL = [
  [
    "Suplantación con SPF correcto",
    "From: Servicio de Seguridad <alertas@bbva-notificaciones.info>\nSubject: Movimiento sospechoso en su cuenta BBVA\nReturn-Path: alertas@bbva-notificaciones.info\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nEstimado cliente, hemos bloqueado un cargo de 812 EUR. Confirme su identidad en https://bbva-notificaciones.info/verificar",
  ],
  [
    "Factura adjunta (proveedor falso)",
    "From: Administracion <facturacion@grupo-suministros.info>\nSubject: Factura pendiente F-2024-8891\nReturn-Path: facturacion@grupo-suministros.info\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nAdjuntamos la factura pendiente. Puede descargarla en https://grupo-suministros.info/factura.pdf.exe",
  ],
  [
    "Microsoft 365: caducidad de contraseña",
    "From: Microsoft 365 <no-reply@m365-avisos.cfd>\nSubject: Su contraseña de Microsoft caduca hoy\nReturn-Path: no-reply@m365-avisos.cfd\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nSu contraseña caduca en 2 horas. Mantengala pulsando aqui: https://m365-avisos.cfd/keep-password",
  ],
  [
    "RRHH interno (fraude del CEO)",
    "From: Direccion Financiera <direccion@empresa-nomina.info>\nSubject: Accion requerida: actualizacion de datos bancarios\nReturn-Path: direccion@empresa-nomina.info\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nNecesitamos que actualice sus datos bancarios para la nomina de este mes en https://empresa-nomina.info/rrhh",
  ],
];

// ---------------- Ficheros: entrega de malware realista ----------------
function bytes(sig, len = 200) {
  return new Uint8Array([...sig, ...new Array(len).fill(0x41)]);
}
const CAMPANAS_FILE = [
  ["Doc con macros (OLE) como .pdf", bytes([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), "Factura_2024.pdf"],
  ["Instalador con doble extensión", bytes([0x4d, 0x5a]), "Contrato_firmado.pdf.exe"],
  ["Screensaver (ejecutable)", bytes([0x4d, 0x5a]), "Nomina_noviembre.scr"],
  ["LNK disfrazado", bytes([0x4c, 0x00, 0x00, 0x00]), "Documento.pdf.lnk"],
  ["ISO (evasión de Mark-of-the-Web)", bytes([0x43, 0x44, 0x30, 0x30, 0x31], 400), "envio_dhl.iso"],
  ["HTML smuggling", new TextEncoder().encode('<html><script>var b=atob("TVqQ");</script></html>'), "factura.html"],

];

const CAMPANAS_URL = [
  ["Subdominio de marca larga", "https://seguridad.cliente.bbva.es.verificacion-online.info/acceso"],
  ["Marca + guiones en .com", "https://correos-seguimiento-envios.com/track"],
  ["Servicio legítimo abusado", "https://firebasestorage.googleapis.com/v0/b/x/o/login.html"],
  ["Acortador conocido", "https://bit.ly/3xPhish"],
  ["Punycode de marca (córreos.es)", "https://xn--crreos-bxa.es/envio"],
];

function u16(n){return [n&0xff,(n>>8)&0xff];}
function u32(n){return [n&0xff,(n>>8)&0xff,(n>>16)&0xff,(n>>24)&0xff];}
async function buildZipWithExe() {
  const enc = new TextEncoder();
  const name = enc.encode("Presupuesto.pdf.exe");
  const data = new Uint8Array([0x4d, 0x5a, ...new Array(50).fill(0)]);
  const local = [...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(data.length), ...u32(data.length), ...u16(name.length), ...u16(0), ...name, ...data];
  const central = [...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
    ...u32(0), ...u32(data.length), ...u32(data.length), ...u16(name.length),
    ...u16(0), ...u16(0), ...u16(0), ...u16(0), ...u32(0), ...u32(0), ...name];
  const eocd = [...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(1), ...u16(1),
    ...u32(central.length), ...u32(local.length), ...u16(0)];
  return new Uint8Array([...local, ...central, ...eocd]);
}

async function run() {
  for (const [nombre, texto] of CAMPANAS_SMS) {
    const r = await checkSms(texto, { networkEnabled: false });
    rec("SMS", nombre, r.verdict, r.riskScore, r.flags);
  }
  for (const [nombre, raw] of CAMPANAS_MAIL) {
    const r = await checkMail(raw, { networkEnabled: false });
    rec("Correo", nombre, r.verdict, r.riskScore, r.flags);
  }
  // ZIP real (no una firma suelta) con un .exe dentro: es como llega el malware por correo.
  const zipConExe = await buildZipWithExe();
  const rz = await checkFile(new File([zipConExe], "Presupuesto.pdf.zip"));
  rec("Archivo", "Ejecutable dentro de un ZIP", rz.verdict, rz.verdict === "dangerous" ? 90 : 0, rz.flags);

  for (const [nombre, data, name] of CAMPANAS_FILE) {
    const r = await checkFile(new File([data], name));
    rec("Archivo", nombre, r.verdict, r.verdict === "dangerous" ? 90 : 0, r.flags);
  }
  for (const [nombre, u] of CAMPANAS_URL) {
    try {
      const r = await checkUrl(u, { networkEnabled: false });
      rec("URL", nombre, r.verdict, r.riskScore, r.flags);
    } catch (e) {
      rec("URL", nombre, "ERROR", 0, [e.message]);
    }
  }

  const fallos = rows.filter((r) => r.verdict === "safe");
  const el = document.getElementById("results");
  el.innerHTML =
    `<p><strong>${fallos.length} de ${rows.length} campañas reales pasan como "safe"</strong> (sin red, estado por defecto)</p>` +
    "<table border='1' cellpadding='6' style='border-collapse:collapse;font-size:13px'>" +
    "<tr><th>Tipo</th><th>Campaña</th><th>Veredicto</th><th>Riesgo</th><th>Señales</th></tr>" +
    rows
      .map((r) => {
        const c = r.verdict === "safe" ? "#f87171" : r.verdict === "suspicious" ? "#fbbf24" : "#34d399";
        return `<tr><td>${esc(r.cat)}</td><td>${esc(r.nombre)}</td><td style="color:${c}"><strong>${esc(r.verdict)}</strong></td><td>${esc(r.score)}</td><td>${esc(r.flags)}</td></tr>`;
      })
      .join("") +
    "</table>";
  console.log("campañas:", JSON.stringify(rows, null, 1));
  window.__campaigns = rows;
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
}

run();
