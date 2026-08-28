// Red team: entradas MALICIOSAS reales que intentan evadir la detección.
// Lo que salga como "safe" aquí es un falso negativo — la herramienta diciendo
// "tranquilo" ante algo que sí es un ataque, que es el fallo más peligroso.
import { checkUrl } from "../public/js/modules/urlModule.js";
import { checkSms } from "../public/js/modules/smsModule.js";
import { checkMail } from "../public/js/modules/mailModule.js";
import { checkFile } from "../public/js/modules/fileModule.js";
import { scanSecrets } from "../public/js/modules/secretsModule.js";

const rows = [];
function rec(mod, tecnica, entrada, verdict, flags) {
  rows.push({ mod, tecnica, entrada, verdict, flags: (flags || []).join(", ") || "—" });
}

const URL_EVASIONS = [
  ["marca como subdominio del atacante", "https://paypal.com.inicio-sesion.net/login"],
  ["marca como subdominio (2)", "https://correos.es.envio-seguimiento.top/track"],
  ["marca dentro de un dominio mayor", "https://paypal-secure-login.com/verify"],
  ["marca dentro de un dominio mayor (2)", "https://bbva-clientes-acceso.com/login"],
  ["marca + palabra en .com legítimo", "https://segsocial-tramites.com/expediente"],
  ["guión y TLD normales", "https://amazon-pedidos.net/rastreo"],
  ["typosquat a distancia 2", "https://payypall.com/login"],
  ["homoglifo latino (I mayúscula por l)", "https://paypaI.com/login"],
  ["marca en la ruta, no en el host", "https://cdn-static-98213.com/paypal.com/login"],
  ["subdominio profundo legítimo-aparente", "https://login.secure.account.paypal.com.verify.io/"],
];

const SMS_EVASIONS = [
  ["sin nombrar la marca", "Tiene un envio pendiente. Abone la tasa de aduana aqui: https://tasas-envio.top/pago"],
  ["carácter de ancho cero dentro de la palabra", "Verifica tu cu​enta en https://acceso-bbva.top/login"],
  ["leetspeak", "Verif1ca tu cuenta bancaria en https://bbva-acceso.top/entrar"],
  ["homoglifo cirílico en el texto", "Verifiса tu cuenta en https://bbva-seguro.top/login"],
  ["sin enlace, con teléfono", "Su cuenta ha sido bloqueada. Llame al 900 123 456 para reactivarla."],
  ["marca escrita separada", "Seg. Social: expediente pendiente https://tramites-seg.top/exp"],
  ["urgencia implícita sin palabras clave", "Su expediente 4417 requiere accion antes del viernes: https://gestion-exp.cfd/e"],
];

const MAIL_EVASIONS = [
  [
    "marca solo en el Subject (no se analiza)",
    "From: Servicio <aviso@correo-notificacion.net>\nSubject: Su cuenta de PayPal ha sido suspendida\nReturn-Path: aviso@correo-notificacion.net\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nAcceda para restablecerla: https://paypal-restablecer.top/login",
  ],
  [
    "marca en el cuerpo sin tono oficial",
    "From: Soporte <no-reply@aviso-servicio.net>\nReturn-Path: no-reply@aviso-servicio.net\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nSu cuenta de Netflix caduca hoy. Renueve en https://netflix-pagos.top/renovar",
  ],
  [
    "nombre mostrado con marca separada",
    'From: "Pay Pal Seguridad" <security@pp-verificacion.net>\nReturn-Path: security@pp-verificacion.net\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nVerifique su cuenta: https://pp-verificacion.net/login',
  ],
];

const FILE_EVASIONS = [
  ["doble extensión (clásico)", new Uint8Array([0x4d, 0x5a, ...new Array(40).fill(0)]), "factura.pdf.exe"],
  ["doble extensión con espacios", new Uint8Array([0x4d, 0x5a, ...new Array(40).fill(0)]), "nomina.pdf     .exe"],
  ["ejecutable con extensión desconocida", new Uint8Array([0x4d, 0x5a, ...new Array(40).fill(0)]), "documento.scr"],
  ["sin extensión", new Uint8Array([0x4d, 0x5a, ...new Array(40).fill(0)]), "instalador"],
];

const SECRET_EVASIONS = [
  ["clave real que contiene 'YOUR'", 'aws_key = "AKIAYOURJ7SHDN2P4KQ1"'],
  ["clave partida en dos", 'const k = "AKIA" + "IOSFODNN7REALKEY99";'],
  ["clave en base64", 'const k = atob("QUtJQUlPU0ZPRE5ON1JFQUxLRVk5OQ==");'],
];

async function run() {
  for (const [t, u] of URL_EVASIONS) {
    try {
      const r = await checkUrl(u, { networkEnabled: false });
      rec("URL", t, u, r.verdict, r.flags);
    } catch (e) {
      rec("URL", t, u, "ERROR", [e.message]);
    }
  }
  for (const [t, s] of SMS_EVASIONS) {
    const r = await checkSms(s);
    rec("SMS", t, s.slice(0, 55) + "…", r.verdict, r.flags);
  }
  for (const [t, m] of MAIL_EVASIONS) {
    const r = await checkMail(m);
    rec("Correo", t, m.split("\n")[0], r.verdict, r.flags);
  }
  for (const [t, bytes, name] of FILE_EVASIONS) {
    const r = await checkFile(new File([bytes], name));
    rec("Archivos", t, name, r.verdict, r.flags);
  }
  for (const [t, code] of SECRET_EVASIONS) {
    const r = scanSecrets(code);
    rec("Secretos", t, code.slice(0, 45), r.verdict, r.findings.map((f) => f.name));
  }

  const escaped = rows.filter((r) => r.verdict === "safe");
  const el = document.getElementById("results");
  el.innerHTML =
    `<p><strong>${escaped.length} de ${rows.length} evasiones se cuelan como "safe"</strong></p>` +
    "<table border='1' cellpadding='6' style='border-collapse:collapse;font-size:13px'>" +
    "<tr><th>Módulo</th><th>Técnica</th><th>Entrada</th><th>Veredicto</th><th>Flags</th></tr>" +
    rows
      .map((r) => {
        const color = r.verdict === "safe" ? "#f87171" : r.verdict === "suspicious" ? "#fbbf24" : "#34d399";
        return `<tr><td>${esc(r.mod)}</td><td>${esc(r.tecnica)}</td><td>${esc(r.entrada)}</td><td style="color:${color}"><strong>${esc(r.verdict)}</strong></td><td>${esc(r.flags)}</td></tr>`;
      })
      .join("") +
    "</table>";
  console.log("evasiones:", JSON.stringify(rows, null, 1));
  window.__evasions = rows;
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = String(s ?? "");
  return d.innerHTML;
}

run();
