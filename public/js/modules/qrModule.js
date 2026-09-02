import { saveResult } from "../db.js";
import { checkUrl } from "./urlModule.js";
import { checkSms } from "./smsModule.js";

// El QR es el único vector donde el usuario NO puede leer lo que va a abrir antes de abrirlo:
// el destino está codificado. Por eso el fraude por QR ("quishing") funciona tan bien pegando
// una pegatina encima del código legítimo de un parquímetro, una multa o la carta de un bar.
// Aquí se decodifica primero y se enseña el contenido en crudo; el análisis viene después.

export const QR_FLAG_POINTS = {
  qr_javascript: 70,
  qr_otpauth: 60,
  qr_payment: 45,
  qr_premium_number: 45,
  qr_wifi_open: 35,
  qr_sms_preescrito: 35,
  qr_data_uri: 40,
  qr_app_deeplink: 25,
  qr_wifi: 10,
  qr_contacto: 10,
};

export const QR_FLAG_LABELS = {
  qr_javascript: "El código contiene 'javascript:' — no es un enlace a una web, es código para que lo ejecute tu navegador. Ningún QR legítimo hace esto",
  qr_data_uri: "El código lleva un 'data:' incrustado: el contenido viaja dentro del propio QR en vez de estar en una web, técnica habitual para colar un archivo o una página falsa sin dominio que delate nada",
  qr_otpauth: "Este QR añade una cuenta a tu app de verificación en dos pasos. Solo debes escanearlo si TÚ acabas de pedirlo en la web del servicio: si te ha llegado por mensaje o estaba pegado en algún sitio, lo que hace es enlazar tu 2FA con algo que controla otra persona",
  qr_payment: "Es una solicitud de pago (cripto o transferencia), con importe y destinatario ya fijados. Comprueba a quién va antes de nada",
  qr_premium_number: "Marca un número de tarificación especial (900/80x/90x): la llamada la pagas tú y puede costar varios euros por minuto",
  qr_sms_preescrito: "Deja un SMS ya escrito listo para enviar. Es como se dan de alta suscripciones de pago sin que te enteres: tú solo pulsas enviar",
  qr_wifi_open: "Conecta a una wifi SIN contraseña. Quien la monta ve el tráfico que no vaya cifrado y puede redirigirte a páginas falsas",
  qr_wifi: "Conecta a una red wifi",
  qr_app_deeplink: "Abre directamente una app o su ficha de instalación, saltándose el navegador",
  qr_contacto: "Añade un contacto a tu agenda",
};

// Prefijos de tarificación especial en España + el 900 (gratuito, pero muy usado como
// señuelo de "atención al cliente" falso, así que se avisa igual).
const PREMIUM_ES = /^(?:\+34|0034)?\s*(80[0-79]|90[0-79])/;

function limpiarNumero(n) {
  return n.replace(/[\s()-]/g, "");
}

// WIFI:T:WPA;S:MiRed;P:clave;H:false;;  — formato de facto, no hay RFC.
function parseWifi(payload) {
  const campos = {};
  for (const trozo of payload.slice(5).split(";")) {
    const sep = trozo.indexOf(":");
    if (sep > 0) campos[trozo.slice(0, sep).toUpperCase()] = trozo.slice(sep + 1);
  }
  return { ssid: campos.S || null, cifrado: (campos.T || "nopass").toLowerCase(), oculta: campos.H === "true" };
}

// Clasifica el contenido del QR. Función pura: no toca red ni DOM, para poder testearla.
export function classifyQrPayload(texto) {
  const t = (texto || "").trim();
  const bajo = t.toLowerCase();

  if (/^javascript:/i.test(t)) return { kind: "javascript", flags: ["qr_javascript"], detalle: t.slice(0, 200) };
  if (/^data:/i.test(t)) return { kind: "data", flags: ["qr_data_uri"], detalle: t.slice(0, 120) };
  if (/^otpauth:\/\//i.test(t)) {
    let cuenta = null;
    try { cuenta = decodeURIComponent(new URL(t).pathname.replace(/^\/+/, "")); } catch { /* etiqueta ilegible */ }
    return { kind: "otpauth", flags: ["qr_otpauth"], detalle: cuenta };
  }
  if (/^(bitcoin|ethereum|litecoin|bitcoincash|monero):/i.test(t)) {
    return { kind: "pago", flags: ["qr_payment"], detalle: t.slice(0, 160) };
  }
  if (/^wifi:/i.test(t)) {
    const w = parseWifi(t);
    const abierta = w.cifrado === "nopass" || w.cifrado === "";
    return { kind: "wifi", flags: abierta ? ["qr_wifi_open"] : ["qr_wifi"], detalle: w.ssid, wifi: w };
  }
  if (/^smsto:/i.test(bajo) || /^sms:/i.test(bajo)) {
    const resto = t.slice(t.indexOf(":") + 1);
    const [numero, ...cuerpo] = resto.split(":");
    const mensaje = cuerpo.join(":");
    const flags = [];
    if (mensaje.trim()) flags.push("qr_sms_preescrito");
    if (PREMIUM_ES.test(limpiarNumero(numero))) flags.push("qr_premium_number");
    return { kind: "sms", flags, detalle: mensaje ? `${numero} — "${mensaje}"` : numero, numero, mensaje };
  }
  if (/^tel:/i.test(t)) {
    const numero = t.slice(4);
    return {
      kind: "tel",
      flags: PREMIUM_ES.test(limpiarNumero(numero)) ? ["qr_premium_number"] : [],
      detalle: numero,
      numero,
    };
  }
  if (/^(market|intent|itms-apps|fb|whatsapp|tg):/i.test(t)) {
    return { kind: "deeplink", flags: ["qr_app_deeplink"], detalle: t.slice(0, 160) };
  }
  if (/^begin:vcard/i.test(bajo) || /^mecard:/i.test(bajo)) {
    return { kind: "contacto", flags: ["qr_contacto"], detalle: null };
  }
  if (/^mailto:/i.test(t)) return { kind: "mailto", flags: [], detalle: t.slice(7, 160) };
  if (/^https?:\/\//i.test(t)) return { kind: "url", flags: [], detalle: t };
  // Sin esquema pero con pinta de dominio: los QR suelen llevar la URL sin "https://".
  if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:[/:?#]|$)/i.test(t) && !/\s/.test(t)) {
    return { kind: "url", flags: [], detalle: `https://${t}`, urlNormalizada: `https://${t}` };
  }
  return { kind: "texto", flags: [], detalle: t.slice(0, 400) };
}

// BarcodeDetector es una API del propio navegador: sin librería, sin subir la imagen a
// ningún sitio. No está en todos los navegadores (Safari no la trae), y en ese caso se dice
// claramente en vez de fallar en silencio.
export function qrSupported() {
  return typeof globalThis.BarcodeDetector !== "undefined";
}

export async function decodeQrFromBlob(blob) {
  if (!qrSupported()) throw new Error("sin_soporte");
  const bitmap = await createImageBitmap(blob);
  try {
    const detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] });
    const codigos = await detector.detect(bitmap);
    if (!codigos.length) throw new Error("sin_codigo");
    return codigos[0].rawValue;
  } finally {
    bitmap.close?.();
  }
}

function verdictoDe(score) {
  return score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe";
}

// El análisis del QR se apoya en las herramientas que ya existen: si dentro hay una URL, la
// analiza checkUrl entera (incluida la resolución del destino si la red está activada); si es
// texto suelto, pasa por las heurísticas de smishing. Un QR no deja de ser un envoltorio.
export async function checkQr(texto, { networkEnabled = false, persist = true } = {}) {
  const clasificacion = classifyQrPayload(texto);
  let anidado = null;
  let flags = [...clasificacion.flags];
  let score = flags.reduce((s, f) => s + (QR_FLAG_POINTS[f] || 0), 0);

  if (clasificacion.kind === "url") {
    anidado = await checkUrl(clasificacion.urlNormalizada || texto.trim(), { networkEnabled, persist: false });
    score = Math.min(100, score + anidado.riskScore);
  } else if (clasificacion.kind === "texto" && texto.trim().length > 12) {
    anidado = await checkSms(texto, { networkEnabled, persist: false });
    score = Math.min(100, score + anidado.riskScore);
  }

  score = Math.min(100, score);

  const result = {
    type: "qr",
    input: texto,
    kind: clasificacion.kind,
    detalle: clasificacion.detalle,
    flags,
    nested: anidado,
    riskScore: score,
    verdict: verdictoDe(score),
    timestamp: Date.now(),
  };
  if (persist) {
    await saveResult({
      type: "qr",
      input: texto,
      verdict: result.verdict,
      riskScore: score,
      flags,
      timestamp: result.timestamp,
      raw: result,
    });
  }
  return result;
}
