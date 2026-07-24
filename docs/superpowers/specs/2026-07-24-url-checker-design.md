# Cerberus — Verificador de URLs acortadas (MVP)

## Contexto
Herramienta web local para verificar URLs acortadas (bit.ly, tinyurl, t.co, etc.): resuelve el destino final siguiendo redirects y aplica heurísticas propias de seguridad, sin depender de APIs externas (VirusTotal, Google Safe Browsing) en esta fase.

## Alcance MVP
- Expandir cadena de redirects hasta destino final
- Heurísticas propias: HTTPS, edad de dominio (WHOIS best-effort), typosquatting (lista hardcoded), patrones de URL sospechosos
- Verdict + risk score basado en puntos
- Interfaz web local (Node.js + Express, frontend vanilla HTML/JS)
- Sin persistencia (stateless), sin login, sin APIs externas de terceros

## Fuera de alcance (futuro)
- Integración VirusTotal / Google Safe Browsing (requiere API key)
- Historial persistente
- Deploy público / multi-usuario
- Extensión de navegador / app de escritorio

## Arquitectura
- Node.js + Express, servido estático desde `public/`
- Single-page vanilla HTML/JS/CSS, sin build step, sin framework frontend
- Endpoint único: `POST /api/check { url }` → JSON resultado

## Componentes

### Backend (`src/`)
- `redirectFollower.js` — sigue redirects manualmente (fetch `redirect: 'manual'`), captura cada hop `{url, statusCode}`, máx 10 saltos, detecta loops
- `heuristics/httpsCheck.js` — flag si algún hop no usa HTTPS
- `heuristics/domainAge.js` — WHOIS best-effort (timeout 3s); si falla/timeout → `null` (no penaliza, no bloquea)
- `heuristics/typosquat.js` — distancia Levenshtein contra `data/known-domains.json` (~50-100 dominios top); match si distancia ≤2
- `heuristics/urlPatterns.js` — IP literal como host, `@` en URL, exceso de guiones/subdominios
- `scorer.js` — combina resultados heurísticas → `{verdict, riskScore, flags[]}`
- `routes/check.js` — orquesta: redirectFollower → heurísticas en paralelo → scorer → responde JSON

### Frontend (`public/`)
- `index.html` + `app.js` + `style.css`
- Layout aprobado (mockup A+C): input + botón centrado arriba, resultado como timeline de redirects abajo (cada hop listado con flecha, destino final marcado, veredicto + flags al pie)
- Fetch a `/api/check`, renderiza timeline + verdict + flags

## Flujo de datos
```
input URL → POST /api/check → redirectFollower (chain)
  → heurísticas en paralelo (https, domainAge, typosquat, patterns)
  → scorer → JSON {chain, verdict, riskScore, flags}
→ frontend renderiza timeline + veredicto
```

## Scoring (basado en puntos)
Base 0 (safe). Suma por flag detectado:

| Flag | Puntos |
|---|---|
| Algún hop sin HTTPS | +30 |
| Dominio nuevo (<30 días) | +40 |
| Dominio edad desconocida (WHOIS falló) | +0 |
| Typosquat match (Levenshtein ≤2 de marca top) | +50 |
| IP literal como host | +40 |
| `@` en URL | +30 |
| >4 redirects | +20 |
| Excesivos guiones/subdominios (>3) | +15 |

Verdict:
- `0-29` → safe
- `30-69` → suspicious
- `70+` → dangerous

## Error handling
- URL inválida (no parsea) → 400, sin llamar heurísticas
- Timeout total del check (8s) → respuesta con `{error: 'timeout', partial: {...}}`
- Redirect loop / >10 hops → corta cadena, flag `redirect_loop`, continúa con lo capturado
- WHOIS falla/timeout → `domainAge: null`, no bloquea resto
- Host no resuelve / conexión rechazada → verdict `dangerous`, flag `unreachable`, no crashea

## Testing
- Unit: cada heurística en `heuristics/*.test.js` — casos puros, sin red real (mock de chain/domain data)
- Unit: `scorer.js` — tabla flags → verdict
- Integration: `routes/check.js` con servidor mock local (nock o servidor de prueba), sin pegar a internet real en CI
- Manual: validar contra bit.ly/tinyurl reales antes de cerrar MVP

## Decisiones clave (de brainstorming)
- Sin API externa en MVP (VirusTotal/Google Safe Browsing) — solo heurísticas propias
- Sin persistencia/historial — stateless
- Layout UI: híbrido opción A (simple centrado) + opción C (timeline de redirects), confirmado vía mockup visual
- Stack: Node.js + Express + HTML/JS vanilla (sin framework frontend)
