// Cirílicos/griegos que se ven igual que una letra latina. Un atacante sustituye una sola
// letra ("Verifiса tu cuenta" con 'с' cirílica) y la palabra deja de coincidir con la lista.
const LOOKALIKES = {
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s",
  ԁ: "d", һ: "h", ӏ: "l", в: "b", к: "k", м: "m", н: "h", т: "t", ν: "v", ο: "o",
  α: "a", ρ: "p", τ: "t", υ: "u", χ: "x", ι: "i", κ: "k",
};

// Utilidades de texto compartidas por smsModule.js y mailModule.js (análisis del cuerpo).
export function normalize(s) {
  return s
    .toLowerCase()
    // Caracteres de ancho cero: invisibles, pero rompían la coincidencia de palabras
    // ("cu​enta" no casaba con "cuenta") sin que se notara nada raro en pantalla.
    .replace(/[\u200b-\u200f\u2060-\u2064\ufeff\u00ad]/g, "")
    .replace(/[\u0400-\u04ff\u0370-\u03ff]/g, (ch) => LOOKALIKES[ch] || ch)
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "");
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
