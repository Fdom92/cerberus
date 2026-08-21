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
  correos: ["correos.es"],
  "seg social": ["seg-social.es"],
  "seguridad social": ["seg-social.es"],
  dgt: ["dgt.es"],
  "agencia tributaria": ["agenciatributaria.gob.es"],
  hacienda: ["agenciatributaria.gob.es"],
  dhl: ["dhl.com"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  facebook: ["facebook.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"],
};
