// Utilidades de texto compartidas por smsModule.js y mailModule.js (análisis del cuerpo).
export function normalize(s) {
  return s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}

export function matchesAny(text, words) {
  const norm = normalize(text);
  return words.some((w) => norm.includes(normalize(w)));
}

export function extractUrls(text) {
  const matches = text.match(/\bhttps?:\/\/[^\s<>"')]+/gi) || [];
  const bare = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')]*)?/gi) || [];
  const all = [...matches];
  for (const b of bare) {
    if (!matches.some((m) => m.includes(b))) all.push(b);
  }
  return [...new Set(all)];
}

// Registro/aviso "oficial" vago — muy común en phishing que suplanta administraciones públicas
// (Seg. Social, Correos, DGT, Agencia Tributaria): tono burocrático en vez de urgencia agresiva.
export const OFFICIAL_NOTICE_WORDS = [
  "actualizacion pendiente", "tramite pendiente", "gestione el tramite", "gestione su tramite",
  "consulte su informacion", "notificacion pendiente", "aviso importante", "accion requerida",
  "action required", "pending procedure", "gestion pendiente",
];
