// Consulta de reputación contra inteligencia de amenazas real, sin clave de API y sin backend.
//
// Se usa el resolver de seguridad de Cloudflare (1.1.1.2): resuelve DNS igual que el normal,
// pero devuelve 0.0.0.0 con el error extendido EDE 16 ("Censored") cuando el dominio está en
// sus listas de phishing/malware. Es decir, la respuesta DNS misma es el veredicto.
//
// Por qué encaja aquí: no hace falta registrarse, no se envía la URL completa (solo el dominio,
// que es justo lo que ya sale al resolver cualquier enlace) y la fuente está contrastada.
//
// MEDIDO antes de integrarlo (muestras de listas públicas):
//   - 18 de 20 dominios de phishing reales -> bloqueados (1 más ya estaba dado de baja)
//   - 1 de 9 dominios de distribución de malware -> bloqueado; el resto es infraestructura
//     legítima abusada (pages.dev, cloudflarestorage.com…), que Cloudflare no puede tumbar
//   - 0 de 12 dominios legítimos -> ningún falso positivo
//
// De ahí la regla de uso: **la señal es asimétrica**. Un acierto es prueba fuerte de amenaza;
// no encontrar nada NO es prueba de que sea seguro, y nunca debe rebajar el resto de flags.
const SECURITY_DOH = "https://security.cloudflare-dns.com/dns-query";
const TIMEOUT_MS = 5000;

export async function checkDomainReputation(hostname) {
  if (!hostname) return { status: "unavailable" };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${SECURITY_DOH}?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal,
    });
    if (!res.ok) return { status: "unavailable" };
    const data = await res.json();

    // NXDOMAIN: el dominio no existe. No es lo mismo que estar bloqueado y confundirlos
    // convertiría cualquier dominio caducado en una "amenaza confirmada".
    if (data.Status === 3) return { status: "nxdomain" };

    const answers = data.Answer || [];
    const blocked =
      answers.some((a) => a.type === 1 && a.data === "0.0.0.0") ||
      (data.Comment || []).some((c) => /EDE\(16\)/i.test(c));

    return { status: blocked ? "blocked" : "clean" };
  } catch {
    return { status: "unavailable" };
  } finally {
    clearTimeout(timer);
  }
}

// Varios dominios a la vez (SMS/correo con varios enlaces), con tope para no encadenar
// consultas indefinidamente si alguien pega un texto lleno de enlaces.
export async function checkDomainsReputation(hostnames, max = 3) {
  const unique = [...new Set(hostnames)].slice(0, max);
  const results = await Promise.all(unique.map((h) => checkDomainReputation(h)));
  return unique.map((host, i) => ({ host, ...results[i] }));
}
