// Marca mencionada en texto (email/SMS) -> dominio(s) real(es) esperado(s).
// Fuente única compartida por mailModule.js y smsModule.js — antes cada uno tenía su propia
// copia y se desincronizaban en silencio (ver docs/superpowers/specs, fix del falso negativo
// de Seg. Social: smsModule tenía "dgt"/"hacienda" y mailModule no).
// Valores como array porque algunas marcas usan legítimamente más de un dominio (ej. Amazon
// España vs EEUU) — un solo string habría generado falsos positivos.
export const BRAND_DOMAINS = {
  paypal: ["paypal.com"],
  google: ["google.com"],
  microsoft: ["microsoft.com"],
  apple: ["apple.com"],
  amazon: ["amazon.com", "amazon.es"],
  netflix: ["netflix.com"],
  santander: ["santander.com", "santander.es"],
  bbva: ["bbva.com", "bbva.es"],
  caixabank: ["caixabank.com", "caixabank.es"],
  // Las administraciones públicas españolas usan tanto el dominio corto como el .gob.es —
  // omitir el real marcaba como suplantación el enlace legítimo (sede.dgt.gob.es).
  correos: ["correos.es"],
  "seg social": ["seg-social.es", "seg-social.gob.es"],
  "seguridad social": ["seg-social.es", "seg-social.gob.es"],
  dgt: ["dgt.es", "dgt.gob.es"],
  "agencia tributaria": ["agenciatributaria.gob.es", "agenciatributaria.es"],
  hacienda: ["agenciatributaria.gob.es", "agenciatributaria.es"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],

  // Añadidas tras probar campañas reales: sin ellas, phishing muy extendido en España
  // (Bizum, eléctricas, operadoras) no dejaba ninguna señal de suplantación.
  bizum: ["bizum.es"],
  endesa: ["endesa.com", "endesa.es"],
  iberdrola: ["iberdrola.es", "iberdrola.com"],
  naturgy: ["naturgy.es", "naturgy.com"],
  repsol: ["repsol.com", "repsol.es"],
  movistar: ["movistar.es", "telefonica.com"],
  vodafone: ["vodafone.es", "vodafone.com"],
  orange: ["orange.es"],
  sabadell: ["bancsabadell.com", "sabadell.com"],
  bankinter: ["bankinter.com", "bankinter.es"],
  openbank: ["openbank.es"],
  unicaja: ["unicaja.es", "unicajabanco.es"],
  ibercaja: ["ibercaja.es"],
  abanca: ["abanca.com"],
  mapfre: ["mapfre.es", "mapfre.com"],
  iberia: ["iberia.com"],
  renfe: ["renfe.com", "renfe.es"],
  glovo: ["glovoapp.com"],
  wallapop: ["wallapop.com"],
  vinted: ["vinted.es", "vinted.com"],
  "el corte ingles": ["elcorteingles.es"],

  // Siglas por las que se conocen las administraciones: el phishing las usa tal cual
  // ("aeat-devoluciones", "sede-inss") y por el nombre completo no se detectaban.
  aeat: ["agenciatributaria.gob.es", "agenciatributaria.es"],
  inss: ["seg-social.es", "seg-social.gob.es"],
};
