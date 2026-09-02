// Preferencia de comprobaciones en red: apagada por defecto y compartida por URLs, QR, SMS y
// Correo. Vive en su propio módulo porque es un ajuste de privacidad y ya se coló una vez que
// un botón dentro de un resultado ("activar y repetir") la dejara encendida de forma
// permanente en las cuatro herramientas, cuando el usuario solo había pedido repetir una
// comprobación. Aquí se puede testear sin montar la interfaz.

export const NET_PREF_KEY = "cerberus_net_enabled";

// Excepción de un solo uso: vale para la comprobación que se lanza justo después y no se
// guarda en ningún sitio. Que quede encendido de verdad es siempre una decisión explícita
// tomada en el interruptor.
let soloEstaVez = false;

export function isNetEnabled() {
  if (soloEstaVez) return true;
  try {
    return localStorage.getItem(NET_PREF_KEY) === "1";
  } catch {
    // Almacenamiento bloqueado (modo privado, cookies de terceros): sin preferencia guardada
    // lo correcto es NO salir a la red.
    return false;
  }
}

// Lo que hay GUARDADO, ignorando la excepción de un solo uso: es lo que debe reflejar el
// interruptor, que representa la decisión duradera y no el estado momentáneo.
export function getStoredNetPref() {
  try {
    return localStorage.getItem(NET_PREF_KEY) === "1";
  } catch {
    return false;
  }
}

export function setNetPref(enabled) {
  try {
    localStorage.setItem(NET_PREF_KEY, enabled ? "1" : "0");
  } catch {
    /* sin persistencia; el interruptor sigue valiendo para esta sesión */
  }
}

// Ejecuta `fn` como si la red estuviera activada, sin tocar la preferencia guardada. El
// análisis lee isNetEnabled() de forma síncrona al construir sus argumentos, antes del primer
// await, pero se envuelve en try/finally para que una excepción tampoco deje el flag colgado.
export async function withNetOnce(fn) {
  soloEstaVez = true;
  try {
    return await fn();
  } finally {
    soloEstaVez = false;
  }
}
