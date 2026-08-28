// Decodificador punycode (RFC 3492) hecho a mano — necesario porque `URL.hostname` ya devuelve
// el dominio en punycode, así que sin decodificar no se puede distinguir un dominio legítimo con
// tildes (mañana.es -> xn--maana-pta.es) de un ataque homógrafo real (аpple.com con 'а' cirílica).
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((BASE - TMIN) * TMAX) >> 1) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

function decodeLabel(input) {
  const output = [];
  const delimiter = input.lastIndexOf("-");
  if (delimiter > 0) {
    for (let i = 0; i < delimiter; i++) output.push(input.charCodeAt(i));
  }

  let i = 0;
  let n = INITIAL_N;
  let bias = INITIAL_BIAS;

  for (let pos = delimiter > 0 ? delimiter + 1 : 0; pos < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) throw new Error("punycode truncado");
      const c = input.charCodeAt(pos++);
      let digit;
      if (c >= 0x30 && c <= 0x39) digit = c - 0x30 + 26;
      else if (c >= 0x61 && c <= 0x7a) digit = c - 0x61;
      else if (c >= 0x41 && c <= 0x5a) digit = c - 0x41;
      else throw new Error("carácter punycode inválido");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const out = output.length + 1;
    bias = adapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

// Devuelve el hostname con las etiquetas xn-- decodificadas a Unicode.
// Si alguna etiqueta no decodifica, la deja tal cual.
export function punycodeToUnicode(hostname) {
  return hostname
    .split(".")
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        return decodeLabel(label.slice(4));
      } catch {
        return label;
      }
    })
    .join(".");
}

function scriptOf(ch) {
  const c = ch.codePointAt(0);
  if (c < 0x80) return /[a-z]/i.test(ch) ? "latin" : null; // dígitos y guiones son neutros
  if ((c >= 0xc0 && c <= 0x24f) || (c >= 0x1e00 && c <= 0x1eff)) return "latin"; // latino extendido (á, ñ, ü, ç…)
  if (c >= 0x370 && c <= 0x3ff) return "greek";
  if (c >= 0x400 && c <= 0x4ff) return "cyrillic";
  if (c >= 0x590 && c <= 0x5ff) return "hebrew";
  if (c >= 0x600 && c <= 0x6ff) return "arabic";
  if (c >= 0x900 && c <= 0x97f) return "devanagari";
  if (c >= 0x3040 && c <= 0x30ff) return "kana";
  if (c >= 0x4e00 && c <= 0x9fff) return "han";
  if (c >= 0xac00 && c <= 0xd7af) return "hangul";
  return "other";
}

// Caracteres invisibles / de control de dirección: nunca legítimos en un dominio.
const INVISIBLE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/;

// Caracteres cirílicos/griegos que se renderizan prácticamente igual que una letra latina.
// Deliberadamente NO incluye letras sin equivalente visual (и, я, ж, ф, δ, λ…): son las que
// distinguen un dominio extranjero legítimo de uno construido para leerse como texto latino.
const CONFUSABLES = new Map(Object.entries({
  а: "a", е: "e", о: "o", р: "p", с: "c", у: "y", х: "x", і: "i", ј: "j", ѕ: "s",
  ԁ: "d", һ: "h", ӏ: "l", ѡ: "w", ԛ: "q", в: "b", к: "k", м: "m", н: "h", т: "t",
  А: "A", В: "B", Е: "E", К: "K", М: "M", Н: "H", О: "O", Р: "P", С: "C", Т: "T",
  У: "Y", Х: "X", І: "I", Ј: "J", Ѕ: "S",
  ο: "o", α: "a", ν: "v", ρ: "p", τ: "t", υ: "u", χ: "x", ι: "i", κ: "k", ω: "w",
  Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H", Ι: "I", Κ: "K", Μ: "M", Ν: "N", Ο: "O",
  Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
}));

// Un dominio internacionalizado legítimo (mañana.es, münchen.de, россия.рф) usa un solo
// alfabeto por etiqueta y contiene letras propias de ese idioma. Se marca cuando:
//  - se mezclan alfabetos dentro de una etiqueta (аpple.com con 'а' cirílica), o
//  - una etiqueta es enteramente no latina pero TODAS sus letras imitan letras latinas
//    (аррӏе.com se lee "apple"), o
//  - contiene caracteres invisibles.
export function analyzeHostnameScripts(hostname) {
  const unicode = punycodeToUnicode(hostname);
  const isIdn = unicode !== hostname;

  if (INVISIBLE.test(unicode)) return { isIdn, unicode, suspicious: true, reason: "invisible" };

  for (const label of unicode.split(".")) {
    const scripts = new Set();
    let letters = 0;
    let confusable = 0;
    for (const ch of label) {
      const s = scriptOf(ch);
      if (!s) continue;
      scripts.add(s);
      letters++;
      if (CONFUSABLES.has(ch)) confusable++;
    }
    if (scripts.size > 1) return { isIdn, unicode, suspicious: true, reason: "mixed_scripts" };
    if (letters > 0 && !scripts.has("latin") && confusable === letters) {
      return { isIdn, unicode, suspicious: true, reason: "latin_lookalike" };
    }
  }

  return { isIdn, unicode, suspicious: false, reason: null };
}
