# Cerberus — Estación de análisis local (MVP: PWA)

## Contexto
Cerberus es una estación de análisis de amenazas: varios módulos independientes (URLs, archivos, correo, apps, SMS) bajo un mismo shell con tabs. Se distribuye como **PWA estática** — un `index.html` que corre en cualquier dispositivo (abierto como archivo, servido por cualquier host estático, o instalado como app), sin backend propio, bajo consumo de recursos.

Este MVP construye el **shell + módulo URLs + módulo Archivos + Historial**, y en una segunda pasada se añadieron **Correo, SMS y un tab de Herramientas** (JWT, contraseñas, decodificador, EXIF) — todo offline. Solo **Apps** (análisis de APK/IPA) queda como "próximamente".

## Decisión clave: sin servidor propio
Seguir la cadena de redirects de una URL acortada y consultar WHOIS/RDAP requiere red hacia dominios de terceros. Un `fetch` cross-origin puro está bloqueado por CORS en la mayoría de acortadores (diseño de seguridad del navegador: una respuesta opaca no expone `response.url` ni headers). Alternativas evaluadas: proxy CORS público, función serverless propia, servidor local opcional, o eliminar la función.

**Elegido: proxy CORS público, opt-in por el usuario.** Mantiene el objetivo "HTML puro, cualquier dispositivo, sin servidor". Trade-off aceptado: la URL a analizar sale del dispositivo hacia un proxy de terceros — por eso es **opt-in explícito** (toggle apagado por defecto) con aviso visible antes de la primera llamada de red.

- Resolución de destino final: `https://api.allorigins.win/get?url=` → JSON con `status.url` (destino final tras redirects) y `status.http_code`. No expone el listado hop-a-hop con código de cada salto (limitación del proxy genérico); se muestra origen → destino final, no timeline completa.
- Edad de dominio: RDAP vía `https://rdap.org/domain/{dominio}` — confirmado con CORS (`Access-Control-Allow-Origin: *`) de extremo a extremo (rdap.org y los RDAP de registro a los que redirige, ej. Verisign). No requiere proxy. Best-effort: timeout 5s, si falla → `null`, no penaliza.
- Todo lo demás (typosquatting, patrones de URL, punycode/homógrafos, IP literal, `@`) es heurística pura sobre el string, 100% offline.

## Alcance MVP
- Shell PWA instalable: `manifest.webmanifest` + `sw.js` (cache-first, funciona offline tras primera carga)
- Tabs: `01 URLs` y `02 Archivos` (funcionales), `03 Historial` (funcional), `04 Correo` / `05 Apps` / `06 SMS` (deshabilitadas, "próximamente")
- Módulo URLs: heurísticas offline + resolución de destino final y WHOIS opt-in (con aviso de red saliente)
- Módulo Archivos: magic bytes — lee cabecera del archivo localmente (FileReader, nunca sale del dispositivo), compara firma real vs extensión declarada, flag si no coinciden (típico de malware disfrazado)
- Historial: guarda resultados de cualquier check en IndexedDB (fallback `localStorage` si IndexedDB no disponible, ej. `file://` en algún navegador), ver/borrar entradas
- Sin login, sin backend propio, sin build step (vanilla HTML/JS/CSS)

## Navegación — rediseño (grid en vez de tabs)
El tab bar horizontal + sub-nav "Herramientas" generaba jerarquía falsa: URLs/Archivos/Correo/SMS parecían de primer nivel y JWT/Contraseña/Decodificador/EXIF quedaban relegados a un cajón "Herramientas", aunque todos son el mismo tipo de cosa (un check). Sustituido por **pantalla de inicio tipo grid** (`panel-home`): tarjetas agrupadas por categoría (Comunicaciones, Archivos y datos, Cuenta y sesión, Próximamente), todas al mismo nivel visual. Tocar una tarjeta abre esa herramienta a pantalla completa con botón "← Inicio". Historial pasa a icono en la topbar (no es un check, es un registro), accesible desde cualquier pantalla.

## Módulos añadidos (offline, sin red)

### Correo (`js/modules/mailModule.js`)
Analiza cabeceras pegadas (raw headers o `.eml` completo): parsing de texto plano, unfolding de líneas continuadas. Comprueba `Authentication-Results` (SPF/DKIM/DMARC pass/fail/missing), coincidencia de dominio From vs Return-Path vs Reply-To, y suplantación de marca (nombre mostrado menciona una marca conocida pero el dominio real no coincide, lista `BRAND_DOMAINS` hardcoded). Guarda en historial.

### SMS (`js/modules/smsModule.js`)
Heurísticas de smishing sobre texto pegado: listas de palabras de urgencia, petición de credenciales y ganchos (premio/reembolso/aduana), extracción de URLs del texto reutilizando las heurísticas offline de `urlModule.js` (`offlineUrlFlags`, exportado para este fin), flag de enlace acortado. Guarda en historial.

### Herramientas (tab con sub-nav, 4 utilidades independientes, **ninguna se guarda en historial** por privacidad)
- **JWT** (`jwtModule.js`): decodifica header/payload base64url, sin verificar firma. Flags: `alg:none`, algoritmo débil, expirado, sin `exp`, `nbf` futuro.
- **Contraseña** (`passwordModule.js`): estimación de entropía (charset × longitud) penalizada por secuencias, repeticiones y lista de contraseñas comunes. Cálculo 100% en memoria, el valor nunca se persiste ni se loguea.
- **Decodificador** (`decodeModule.js`): prueba Base64, Base64url, Hex y URL-decode sobre el texto pegado, muestra todas las interpretaciones válidas y "mayormente imprimibles".
- **EXIF** (`exifModule.js`): parser JPEG/TIFF hand-rolled (IFD0 + Exif SubIFD + GPS IFD, big/little endian) — Make, Model, fecha, y sobre todo **coordenadas GPS** si las hay (flag destacado: revela dónde se tomó la foto). Validado con JPEG sintético construido a medida (sin depender de una librería externa).

### Secretos (`js/modules/secretsModule.js`)
Escáner de secretos sobre texto/código pegado (AppSec): regex por proveedor (AWS, GitHub, GitLab, Slack, Stripe, Google/Firebase, Twilio, SendGrid, Mailgun, npm, bloques de clave privada) más un catch-all genérico `api_key=...`/`secret=...`. Valores mostrados redactados (`AKIA…MNOP`). No se guarda en historial — mismo motivo que Contraseña/JWT.

### Apps (`js/modules/appsModule.js`) — antes "próximamente", ya implementado (APK + IPA)
Tres capas:
- **v1 — cualquier binario**: extrae strings imprimibles (ASCII y UTF-16LE, como `strings` de Unix) de los primeros 20MB del archivo y corre `scanSecrets` sobre ellas. Funciona con .apk, .ipa, .exe, .dylib, lo que sea.
- **v2 — APK (Android)**: si el ZIP contiene `AndroidManifest.xml`, lo extrae (`js/zipReader.js`: lector de directorio central ZIP hecho a mano, soporta STORED y DEFLATE vía `DecompressionStream` nativo, sin librería externa) y lo parsea (`js/axmlParser.js`: parser mínimo del formato Android Binary XML — string pool + chunks START_ELEMENT/END_ELEMENT) para sacar `package` y todos los `uses-permission`. Cruzado contra ~19 permisos peligrosos (SMS, cámara, micrófono, accesibilidad, ubicación en segundo plano...).
- **v3 — IPA (iOS)**: si el ZIP tiene `Payload/*.app/Info.plist`, lo extrae y parsea (`js/plistParser.js`: soporta binary plist `bplist00` — formato de objetos/offset-table/trailer típico de builds de Xcode — y plist XML vía `DOMParser` como fallback). `CFBundleIdentifier` = paquete; cualquier clave que termina en `UsageDescription` = permiso declarado (así es como iOS declara permisos: la propia presencia de `NSCameraUsageDescription` etc. es la declaración). Cruzado contra ~18 claves peligrosas equivalentes (cámara, micro, contactos, ubicación siempre, salud...).

Verdict combinado = el peor de (secretos encontrados, permisos/usage-descriptions peligrosos). Los tres parsers a medida (`zipReader.js`, `axmlParser.js`, `plistParser.js`) se validaron construyendo ZIP/AXML/bplist sintéticos byte a byte en el navegador antes de darlos por buenos — mismo enfoque que el test sintético de EXIF, ahora formalizado en `tests/`.

## Suite de tests de regresión (`tests/`)
Sin build step ni framework: `tests/index.html` carga `tests/run.js` (módulo ES) que importa los módulos reales de `public/js/` y los ejercita contra fixtures sintéticos (`tests/fixtures.js`: JPEG/ZIP/AXML/bplist construidos byte a byte, mismo código que se usó para validar manualmente cada parser durante el desarrollo). Arnés mínimo propio (`tests/harness.js`, `test()`/`assert()`/`runAll()`) — pass/fail visual en la página + consola. Se abre con `python3 -m http.server` desde la raíz del repo o directamente en cualquier navegador.

25 tests cubren los 12 módulos. La suite ya encontró y arregló 2 bugs reales:
- `getKnownDomains()` en `urlModule.js` hacía `fetch("data/known-domains.json")` relativo al **documento** que importa el módulo — funcionaba desde `public/index.html` pero rompía (404 silencioso → lista vacía) al importarlo desde `tests/`. Arreglado con `fetch(new URL("../../data/known-domains.json", import.meta.url))`, relativo al **módulo**, correcto sin importar quién lo importe.
- El umbral de typosquat (Levenshtein ≤2) generaba falsos positivos entre marcas legítimas cercanas entre sí en `known-domains.json` (github.com/gitlab.com, x.com/t.co, x.com/vk.com, todas a distancia 2). Bajado a ≤1 — sigue cazando sustituciones de un carácter (`goog1e.com`, `paypa1.com`) sin colisionar con las ~60 marcas de la lista.

### Iconos
`icons/icon-180.png` (apple-touch-icon), `icons/icon-192.png` y `icons/icon-512.png` (manifest, `any`+`maskable`) generados desde `icon.svg` vía `qlmanage -t` (no había rasterizador SVG en el entorno) + `sips` para el resize final. El SVG original se mantiene como icono vectorial primario (`rel="icon"`).

### Archivos — ampliado
`fileModule.js` ahora además de magic bytes calcula: SHA-256 completo (`crypto.subtle.digest`, omitido si el archivo supera 50MB para no bloquear el hilo en móvil) y entropía de Shannon sobre los primeros 256KB — entropía >7.5 bits/byte en un ejecutable se flagea como `high_entropy_executable` (indicio de empaquetado/cifrado, técnica común para evadir firmas).

## Botones de ejemplo ("Probar seguro" / "Probar malicioso")
Cada panel de herramienta tiene 1-2 botones que rellenan (y para formularios, envían) un caso de ejemplo, para probar la app sin tener que buscar/crear datos de prueba. Todo en `js/sampleData.js`:
- **Texto** (URLs, Correo, SMS, JWT, Decodificador, Secretos, Contraseña): strings hardcoded, botón rellena el campo y dispara `submit`/`input`.
- **Archivos** (Archivos, EXIF, Apps): generadores que construyen un `File` en memoria reutilizando los mismos builders byte-a-byte de `tests/fixtures.js` (PDF real vs `.exe` renombrado `.pdf`, JPEG con/sin GPS, APK/IPA con permisos peligrosos + secreto embebido) — mismo `handle(file)` que usa drag&drop, cero código nuevo de procesamiento.

19 botones en total, probados uno a uno vía UI real (click → resultado renderizado), no solo la lógica subyacente.

## Fuera de alcance (futuro)
- Integración VirusTotal / Google Safe Browsing (requiere API key)
- Timeline hop-a-hop completa de redirects (requeriría proxy propio, no genérico)
- Sync de historial entre dispositivos (queda local al dispositivo/navegador)
- EXIF: solo JPEG por ahora (PNG usa un chunk `eXIf` distinto, no implementado)

## Arquitectura
- Estático puro: `index.html` + `manifest.webmanifest` + `sw.js` + `css/` + `js/`, sin servidor, sin build step
- Service Worker cachea el shell (HTML/CSS/JS/iconos) — app usable offline salvo los dos checks de red opt-in
- Persistencia: IndexedDB (`js/db.js`), un store `results` con `{id, type, input, verdict, riskScore, flags, timestamp, raw}`
- Módulos independientes en `js/modules/*.js`, orquestados por `js/app.js` (router de tabs simple, sin framework)

## Componentes

### `js/app.js`
Shell: navegación por tabs, monta/desmonta el módulo activo, registra el Service Worker.

### `js/db.js`
`saveResult(entry)`, `listResults()`, `deleteResult(id)`, `clearAll()`. IndexedDB con fallback a `localStorage` (try/catch al abrir DB).

### `js/modules/urlModule.js`
- Heurísticas offline (siempre activas):
  - HTTPS del string introducido
  - Host = IP literal
  - `@` en la URL
  - Exceso de guiones/subdominios (>3)
  - Punycode/homógrafo (`xn--` en host, o mezcla de scripts unicode sospechosa)
  - Typosquatting: distancia Levenshtein ≤1 contra `data/known-domains.json` (~50-100 dominios top)
- Heurísticas opt-in (toggle "activar comprobaciones de red", off por defecto):
  - Resolver destino final vía allorigins (timeout 6s, error → `null`, flag `resolve_failed`)
  - Edad de dominio vía RDAP (timeout 5s, error → `null`, no penaliza)
- `scorer.js` combina flags → `{verdict, riskScore, flags[]}`, igual que antes

### `js/magicBytes.js` + `js/modules/fileModule.js`
- DB de firmas (hex prefijo → tipo): PDF, ZIP/DOCX/XLSX/PPTX/APK/JAR (todos ZIP-based, se distingue por contenido interno si se quiere en fase 2), PNG, JPEG, GIF, BMP, ICO, ELF, PE (exe/dll), Mach-O, RTF, GZIP, 7Z, RAR, MP3, MP4, WAV, class (Java)
- Lee primeros 64 bytes con `FileReader.readAsArrayBuffer` (nunca sale del dispositivo)
- Compara tipo real detectado vs extensión del nombre de archivo → flag `extension_mismatch` si no coinciden (ej. `factura.pdf` que en realidad es un `.exe`)
- Drag&drop + `<input type=file>`

### `js/modules/historyModule.js`
Lista resultados guardados (más reciente primero), click para ver detalle, borrar individual o todo.

## Scoring — módulo URLs (basado en puntos)
Base 0 (safe). Suma por flag detectado:

| Flag | Puntos | Modo |
|---|---|---|
| Punycode/homógrafo | +50 | offline |
| Typosquat match (Levenshtein ≤1) | +50 | offline |
| IP literal como host | +40 | offline |
| `@` en URL | +30 | offline |
| Sin HTTPS | +30 | offline |
| Excesivos guiones/subdominios (>3) | +15 | offline |
| Dominio nuevo (<30 días, RDAP) | +40 | opt-in red |
| Resolución de destino falló | +10 | opt-in red |
| Edad de dominio desconocida | +0 | opt-in red |

Verdict: `0-29` safe · `30-69` suspicious · `70+` dangerous

## Scoring — módulo Archivos
- Firma no reconocida → `unknown`, riesgo bajo por defecto (no penaliza, solo informa)
- Extensión declarada ≠ tipo real detectado → `dangerous`, flag `extension_mismatch`
- Ejecutable (PE/ELF/Mach-O) con extensión no ejecutable → `dangerous`, flag `executable_disguised`
- Firma coincide con extensión → `safe`

## Error handling
- URL inválida (no parsea) → error inline, no llama heurísticas
- Red opt-in desactivada → solo heurísticas offline, sin llamadas salientes
- Timeout resolución destino (6s) / RDAP (5s) → `null` en ese campo, resto del check continúa
- Archivo vacío o <4 bytes → `unknown`, sin crash
- IndexedDB no disponible → fallback silencioso a `localStorage`; si tampoco, historial deshabilitado con aviso

## Testing
- Manual: abrir `index.html` directo (`file://`) y vía servidor estático, verificar ambos casos
- Manual: validar contra bit.ly/tinyurl reales con red opt-in activada
- Manual: probar magic bytes con archivos reales (pdf, exe renombrado a .pdf, zip, png) y aviso de mismatch
- Manual: guardar resultados, recargar página, confirmar persistencia; probar en móvil (viewport + install PWA)

## Decisiones clave (de esta sesión)
- Pivote de "servidor Node/Express local" a **PWA 100% estática**, para poder abrirse en cualquier dispositivo sin instalar nada
- Red solo para 2 checks puntuales (resolver destino final, WHOIS/RDAP), **opt-in y con aviso**, resto 100% offline y privado (magic bytes nunca sale del dispositivo)
- RDAP (`rdap.org`) confirmado con CORS de extremo a extremo, no necesita proxy
- Resolución de destino final vía proxy CORS público (allorigins) — se acepta la limitación de no tener timeline hop-a-hop, solo origen→destino final
- Historial vía IndexedDB con fallback localStorage, sin sync remoto
- Stack: HTML/CSS/JS vanilla, sin build step, sin framework, Service Worker para offline
