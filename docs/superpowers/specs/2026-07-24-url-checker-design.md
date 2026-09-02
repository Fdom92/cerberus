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

## Red team con campañas reales — de 9 coladas a 2
Última pasada, y la más realista: en vez de evasiones sintéticas de heurísticas sueltas,
**30 campañas completas tal y como llegan en España** (`tests/campaign-audit.html`), probadas en el
estado **por defecto** (red apagada), que es como la va a tener casi todo el mundo. En la primera
pasada **9 de 30 salían `safe`**, todas ellas campañas que circulan ahora mismo.

Lo que faltaba, por orden de impacto:

- **Marcas españolas ausentes.** Bizum, Endesa, Iberdrola, Movistar, Vodafone, Sabadell, Bankinter,
  MAPFRE, Renfe, Wallapop… El phishing de Bizum y el de las eléctricas es de los más extendidos y no
  dejaba ninguna señal. Añadidas ~25 marcas, más las **siglas** (`aeat`, `inss`) que es como las
  escriben los dominios de phishing.
- **La estafa del "hijo en apuros"** ("hola mamá, se me ha roto el móvil, este es mi número nuevo").
  Probablemente la estafa más extendida hoy en España, y no tenía absolutamente nada que la
  detectase: sin enlace, sin marca, sin urgencia clásica. Heurística propia con tres señales
  (familiar + número nuevo + petición de dinero), de las que bastan dos.
- **Enlace directo a un ejecutable** (`.../factura.pdf.exe`). Cazó el correo de "factura de
  proveedor" que pasaba con 0 puntos. Ojo con la lista: incluir `js` y `com` provocó 3 falsos
  positivos inmediatos (toda web carga `.js`, y una query que acaba en un email termina en `.com`).
- **El asunto no entraba en las heurísticas de texto**, y ahí es donde el fraude del CEO pone
  "Acción requerida". Añadido también `credential_request` para correo ("actualice sus datos
  bancarios"), que es la carga útil típica.
- **Marca pegada a otras palabras** (`sedeseg-social.online`): el token exacto no aparecía. Ahora se
  busca como subcadena, pero **solo en etiquetas con guión**, para que `amazonas.com` no salte.
- **Ejecutable dentro de un ZIP.** El contenedor es un ZIP legítimo, así que pasaba limpio; lo
  peligroso es lo que lleva dentro. Se listan las entradas con `zipReader` y se marcan las
  ejecutables.
- **ISO/IMG**: formato de entrega de malware muy usado porque su contenido se salta el aviso de
  Windows de "archivo descargado de internet". Se marca sospechoso con un mensaje que distingue el
  caso legítimo (bajarse una ISO de Linux) del peligroso (recibirla por correo).
- **HTML smuggling**: un `.html` que reconstruye un ejecutable con JavaScript para saltarse los
  filtros de correo. Se detecta por contenido (`<script>` + `atob`/`base64`/`Uint8Array`).

**Lo que sigue pasando (2 de 30), y por qué:**
- *Servicio legítimo abusado* (`firebasestorage.googleapis.com/...`): es un dominio real de Google.
  Marcarlo implicaría marcar medio internet.
- *Acortador a secas*: 20 puntos, por debajo del umbral. La respuesta útil aquí no es el veredicto
  sino la vista previa (abajo).

## Acortadores: por qué no se resuelve la cadena, y qué se hace en su lugar
Un usuario reportó que la resolución del destino final **siempre daba timeout**. Comprobado, y era
peor de lo que parecía: `api.allorigins.win` devuelve **522** (su origen caído), el Worker público de
CORS **429**, `cors.lol` **429**, y los dos servicios que sí dan la cadena completa
(`unshorten.me`, `redirect-checker.net`) **no envían cabeceras CORS**, así que el navegador los
bloquea. **No existe hoy un proxy CORS gratuito fiable**: seguir redirecciones desde una app sin
servidor propio no es viable.

Dos consecuencias:
1. **`resolve_failed` deja de puntuar (10 → 0).** Que *nuestro* proxy se caiga no dice absolutamente
   nada sobre el enlace, y estaba sumando puntos a cualquier URL analizada. El mensaje ahora explica
   que es una limitación de la app, no una señal.
2. **Vista previa oficial del acortador.** Avisar de "esto es un acortador" sin decir a dónde lleva
   no le sirve a nadie. Los propios servicios exponen una página de vista previa
   (`bit.ly/xxx+`, `preview.tinyurl.com/xxx`) que muestra el destino **sin seguirlo**. No podemos
   leerla (sin CORS), pero sí ofrecerla como enlace: el usuario aterriza en el acortador, no en el
   destino. Es la única forma honesta de dar la información sin backend.

**Corrección posterior — sí se puede sin backend.** La conclusión anterior estaba mal por un error
de método: las pruebas con `curl` no enviaban cabecera `Origin`, y varios proxies la exigen. Al
repetirlas correctamente apareció **Microlink** (`api.microlink.io`): `access-control-allow-origin: *`,
sin registro, y devuelve `data.url` con el destino ya resuelto tras seguir todas las redirecciones.
Límite medido: **25 consultas al día por IP** — de sobra para uso personal.

Así que el destino final **sí se muestra**, sin servidor propio:
`https://tinyurl.com/2p8s7hfa → https://docs.google.com/gview?...`

Y lo más importante: **las heurísticas se vuelven a aplicar sobre el destino resuelto**. Un `bit.ly`
que apunta a `bbva-clientes-acceso.com` pasaba limpio (bit.ly no tiene nada sospechoso) y ahora
hereda `brand_in_hostname` del destino.

Lo único que sigue necesitando backend es el detalle **salto a salto** (los servicios que lo dan,
`unshorten.me` y `redirect-checker.net`, no mandan CORS). Es lo de menos: para decidir si abrir un
enlace, lo que importa es dónde acaba.

## Reputación: de heurística a dato contrastado (`js/reputation.js`)
Hasta aquí todo eran heurísticas: se juzgaba **la forma** del enlace. Esto añade lo otro — saber si
**ese dominio concreto** está reportado como malicioso — que es el único salto real hacia un
veredicto.

**Cómo, sin backend ni clave de API:** el resolver de seguridad de Cloudflare (1.1.1.2) resuelve DNS
normal pero devuelve `0.0.0.0` con el error extendido `EDE(16): Censored` cuando el dominio está en
sus listas de phishing/malware. La propia respuesta DNS es el veredicto. No hay que registrarse, y
solo sale el dominio — exactamente lo que ya sale al resolver cualquier enlace. Misma filosofía que
la comprobación de contraseñas con HIBP.

**Medido antes de integrarlo** (muestras de listas públicas, no promesas del proveedor):

| Muestra | Resultado |
|---|---|
| 20 dominios de **phishing** reales | **18 bloqueados**, 1 ya dado de baja, 1 escapado |
| 9 dominios de **distribución de malware** | 1 bloqueado — el resto es infraestructura legítima abusada (`pages.dev`, `cloudflarestorage.com`) que Cloudflare no puede tumbar |
| 12 dominios legítimos | **0 falsos positivos** |

Es decir: **muy buena cobertura justo en el caso de uso de esta app** (phishing), pobre en malware.

**La regla que gobierna su uso es la asimetría.** Un acierto es prueba fuerte (80 puntos, basta por
sí solo para `dangerous`). No encontrar nada **no es prueba de nada** y nunca resta puntos: el
phishing recién creado tarda horas o días en entrar en las listas. La interfaz lo dice con esas
palabras — *"no aparece en las listas… eso no garantiza que sea seguro"*— porque presentarlo como
"limpio" a secas sería la falsa tranquilidad que toda esta serie de auditorías intenta evitar.

Integrado en **URLs, SMS y Correo** bajo el mismo interruptor de red, ahora compartido y sincronizado
entre los tres paneles (antes vivía solo en URLs). El valor se ve mejor en SMS: un mensaje sin
ninguna señal offline —sin urgencia, sin marca, con un dominio de aspecto normal— pasa de `safe (0)`
a `dangerous (80)` cuando el dominio está realmente reportado. Un caso que las heurísticas no podían
cazar de ninguna manera.

Otro efecto: `NXDOMAIN` (dominio inexistente) se distingue explícitamente de "bloqueado". Confundirlos
convertiría cualquier dominio caducado en una "amenaza confirmada".

## Auditoría de evasiones (red team) — de 18 coladas a 3
Las auditorías anteriores comprobaban que no diera falsos positivos y que no fuera vulnerable.
Faltaba la contraria: **atacarla a propósito**. `tests/evasion-audit.html` lanza 27 ataques reales
construidos para esquivar cada heurística. En la primera pasada **18 de 27 salían `safe`** — la
herramienta era mucho más débil ante un atacante que se esforzara que ante phishing ingenuo.

Lo más grave, y lo que más se ve en la vida real:

- **`paypal.com.inicio-sesion.net`** — la marca de subdominio y el dominio real del atacante. Es
  *la* forma de dominio de phishing más común y pasaba completamente limpia.
- **`bbva-clientes-acceso.com`** — el nombre de la marca metido en un dominio ajeno. Igual de común,
  igual de invisible.

Ambas se cierran comparando contra el **dominio registrable** (última etiqueta significativa, con
los sufijos tipo `.gob.es` contemplados), que es justo lo que evita el falso positivo: `amazon.de`
y `sede.dgt.gob.es` conservan la marca en su primera etiqueta y no saltan, mientras que
`amazon-pedidos.net` sí.

Resto de evasiones cerradas:
- **Doble extensión** (`factura.pdf.exe`): el disfraz más antiguo que existe. No había discrepancia
  de firma que detectar —el fichero *es* un .exe— así que lo que se analiza es el **nombre**.
- **El `Subject` no se leía**, y es justo donde se pone la marca suplantada.
- **Caracteres de ancho cero y homoglifos cirílicos** dentro de las palabras clave: `cu​enta`
  y `Verifiсa` (с cirílica) rompían la coincidencia sin verse en pantalla. `normalize()` los limpia.
- **Marca escrita separada** ("Pay Pal", "Seg. Social"): se compara también sin espacios ni puntos.
- **Estafa telefónica sin enlace** ("llame al 900…"): no dejaba ninguna señal, y es cada vez más común.
- **Typosquat a distancia 2** (`payypall.com`): restaurado. Los falsos positivos que obligaron a
  bajarlo a 1 venían de comparar marcas legítimas entre sí; con dos guardas (host que ya es o es
  subdominio de un dominio conocido, y misma primera etiqueta en otro TLD) el umbral 2 es seguro.
- **Secretos**: el filtro de placeholders ocultaba una clave real que contuviera "your", así que
  para los patrones con prefijo de proveedor (alta confianza) ahora solo se descarta ante relleno
  evidente. Y se decodifican las tiras base64 para encontrar claves escondidas ahí.

**Lo que sigue colándose, y por qué se acepta:**
- *Marca en la ruta* (`otro-dominio.com/paypal.com/login`): lo que manda es el dominio, y los sitios
  legítimos llevan nombres de marca en las rutas continuamente. Marcarlo daría falsos positivos.
- *Urgencia implícita sin palabras clave* ("su expediente requiere acción antes del viernes"):
  límite de fondo de cualquier detección por palabras — el atacante solo tiene que reformular.
- *Clave partida en el código* (`"AKIA" + "IOSF..."`): haría falta evaluar el código, fuera del
  alcance de un escáner de expresiones regulares.

Tras estos cambios el corpus de entradas legítimas **sigue en 0 falsos positivos**, que era la
condición: endurecer la detección sin volver a molestar con cosas normales.

## Auditoría de publicación (entradas hostiles y veracidad de las afirmaciones)
Antes de publicar, una segunda auditoría sobre lo que no cubría la de falsos positivos: que la
propia app no sea vulnerable y que no afirme cosas que no cumple. `tests/hostile-audit.html`
lanza payloads XSS, entradas malformadas, ficheros vacíos y un APK manipulado contra todos los
módulos. Salieron 4 problemas reales:

- **XSS almacenado en el historial.** `renderDetail()` interpolaba los flags sin escapar. Hoy solo
  llegan claves internas, así que no era explotable — pero el sink estaba vivo y bastaba con que un
  módulo futuro guardase un flag con datos del fichero analizado. La sonda lo confirmó ejecutando
  código (`xssFired: true`) y el historial **persiste en IndexedDB**, así que se habría re-ejecutado
  en cada visita. Escapado.
- **Contaminación de prototipo en los permisos de APK.** `severityMap[p]` con `p` sacado del
  manifest: un permiso llamado `toString` o `constructor` heredaba un valor del prototipo, pasaba el
  filtro y se marcaba como peligroso sin estar en la lista. Corregido con `Object.hasOwn`.
- **Mensajes de error internos del navegador en pantalla.** Una URL como `http://` o
  `javascript:alert(1)` propagaba `TypeError: Failed to construct 'URL'` a la interfaz, en inglés.
  Ahora `parseUrl` valida esquema y dominio y devuelve un mensaje claro; además solo acepta
  `http`/`https`.
- **RangeError con imágenes truncadas.** El parser EXIF leía fuera de límites con un JPEG corrupto y
  el error del navegador acababa en la interfaz. Ahora se captura y se informa de que los metadatos
  no se han podido leer.

**Veracidad de las afirmaciones.** El pie ponía "100% local · sin cuentas · red desactivada" de
forma permanente, y el indicador solo reflejaba el interruptor del módulo URLs. Pero DNS, la
comprobación de contraseña filtrada (HIBP) y la de fuga WebRTC contactan servicios externos aunque
ese interruptor esté apagado: alguien consultando un dominio veía "100% local · red desactivada"
mientras el dominio se enviaba a Cloudflare. En una herramienta que se vende como privada eso es
justo lo que destruye la confianza cuando alguien lo descubre. El pie pasa a "Sin cuentas ni
servidores propios · cada herramienta indica si necesita red" y el indicador dice explícitamente
`URL: sin red` / `URL: con red`, que es lo único que realmente representa.

## Auditoría de falsos positivos (antes de compartir la app públicamente)
Hasta aquí todo el esfuerzo había ido a *no dejar pasar* amenazas. Antes de publicar se hizo la
auditoría inversa: un corpus de entradas **legítimas reales** (`tests/fp-audit.html`) contra todos
los módulos, partiendo de que una herramienta que grita "peligroso" ante cosas normales entrena a
la gente a ignorarla — y entonces es peor que no tener nada. Salieron **21 falsos positivos**, y se
corrigieron todos. Los de más impacto:

- **SMS marcaba los códigos 2FA legítimos.** `CREDENTIAL_WORDS` incluía "codigo de verificacion",
  "contraseña" y "password" a secas, así que "Tu código de verificación es 847362" — probablemente
  el SMS legítimo más frecuente que existe — salía como sospechoso, igual que "Tu contraseña se ha
  cambiado correctamente". La lista pasa a contener solo frases que **piden** la credencial
  ("introduce tu", "verifica tu cuenta"). Entregar un código es normal; pedir que lo introduzcas
  en algún sitio es lo que delata el phishing.
- **Cualquier dominio con tilde se marcaba como homógrafo.** `URL.hostname` devuelve punycode, así
  que la comprobación `host.includes("xn--")` marcaba `mañana.es`, `münchen.de` y `café.fr` como
  ataque — muy relevante en español. Se escribió un **decodificador punycode a mano** (`js/punycode.js`,
  RFC 3492) para poder mirar el dominio real: ahora solo se marca si se **mezclan alfabetos** dentro
  de una etiqueta (`аpple.com` con 'а' cirílica) o si una etiqueta es enteramente no latina pero
  todas sus letras imitan latinas (`аррӏе.com` se lee "apple"). Un dominio ruso legítimo como
  `россия.рф` contiene letras sin sosia latino, y por eso no salta.
- **El '@' de la ruta o la query se confundía con el de userinfo.** Se comprobaba sobre la URL
  entera, así que `?email=juan@example.com` o un paquete npm `paquete@1.0.0` (jsDelivr) se
  marcaban. Ahora solo cuenta `url.username`/`url.password`, que es el '@' que realmente oculta
  el host.
- **Todo instalador legítimo salía "dangerous".** Prácticamente cualquier instalador (NSIS, Inno
  Setup, Electron) va comprimido y supera el umbral de entropía. El flag se renombró a
  `packed_executable`, es informativo y ya **no cambia el veredicto** por sí solo: solo agrava
  cuando el archivo además venía disfrazado con otra extensión.
- **Correo marcaba los boletines normales.** Un `Return-Path` del proveedor de envío y un
  `Reply-To` distinto son el comportamiento estándar de Mailchimp/SendGrid y de cualquier lista de
  correo (pesos bajados 20→8 y 25→10), y mencionar una marca de pasada ("síguenos en Facebook") no
  es suplantarla: `brand_domain_mismatch` ahora exige que el mensaje además **se presente** como esa
  entidad (marca en el nombre mostrado, o tono de aviso oficial).
- **El enlace legítimo de la DGT se marcaba como suplantación**, porque la lista tenía `dgt.es` pero
  el dominio real es `dgt.gob.es`. Añadidos los `.gob.es` de todas las administraciones.
- **Un TLD abusado bastaba para sospechar** (30 pts): `abc.xyz`, que es de Alphabet, salía marcado.
  Bajado a 15 — suma, pero no alcanza el umbral en solitario.
- **Los placeholders de documentación se marcaban como claves reales** (`sk-XXXXXXXX`,
  `api_key: "YOUR_API_KEY_HERE"`). Filtro de placeholders deliberadamente **conservador**: no filtra
  por subcadenas que aparecen dentro de claves legítimas ("abcdef" es hex normal), porque es peor
  ocultar una clave real que mostrar un placeholder de vez en cuando.
- **La clave *publishable* de Stripe** (`pk_live_`) se trataba como secreto filtrado, cuando está
  diseñada para ir en el JavaScript público del checkout. Eliminada del escáner.
- **WebRTC daba "fuga detectada" en conexiones dual-stack normales**, al comparar la IPv6 que ve el
  STUN con la IPv4 de la petición HTTPS. Ahora solo compara direcciones de la misma familia.
- **DNS marcaba sospechosa cualquier web sin correo.** Un dominio sin MX no envía email: que no
  tenga SPF/DMARC es lo esperable, no un problema. Solo se evalúa la higiene de correo si el
  dominio **tiene** MX (`github.io` pasó de sospechoso a seguro).
- Menor: el decodificador convertía palabras normales ("test", "deadbeef") en garabatos y los
  presentaba como hallazgo; ahora exige que el resultado parezca texto de verdad. Añadidas firmas
  WebP/HEIC/AVIF/SQLite (las fotos de iPhone y las imágenes web caían en "desconocido"), colocadas
  **antes** de MP4 porque comparten la caja `ftyp`.

Resultado: **0 falsos positivos** en el corpus, y todas las detecciones reales siguen funcionando
(se verificó con una batería de phishing/malware auténtico después de cada cambio). 42 tests.

## Repaso de gaps tras el fix de SMS — 6 huecos más cerrados
Después del fix de Seg. Social se hizo un repaso del resto de módulos buscando el mismo patrón (heurística demasiado estrecha, lista desincronizada, o código muerto). Encontrados y arreglados:

- **Correo no analizaba el cuerpo del mensaje**, solo cabeceras — si SPF/DKIM pasaban (remitente comprometido o servicio de envío legítimo mal usado) pero el cuerpo enlazaba a un sitio de phishing, no se detectaba nada. `mailModule.js` ahora extrae URLs del cuerpo, corre `offlineUrlFlags` sobre ellas, y aplica los mismos `official_notice_language` / `brand_domain_mismatch` que SMS.
- **`BRAND_DOMAINS` duplicado y desincronizado** entre `mailModule.js` y `smsModule.js` — exactamente la clase de bug que causó el gap original. Extraído a `js/brandDomains.js`, fuente única, valores como array de dominios aceptados (evita falsos positivos tipo "Amazon España vs Amazon EEUU"). `official_notice_language`/`extractUrls`/`normalize` extraídos igual a `js/textHeuristics.js`, compartido por ambos módulos.
- **`magicBytes.js` sin firma OLE/CFB** (`D0 CF 11 E0`) — .doc/.xls/.ppt antiguos y **.msi** cataban a "unknown" sin detección alguna. De paso, se corrigió un error real: "msi" estaba listado en las extensiones esperadas de la firma **PE** (`4D 5A`), pero un MSI genuino nunca lleva cabecera PE — es un contenedor OLE, formato completamente distinto. Ahora tiene su propia entrada, `executable: true`.
- **Apps (Android)** le faltaban `BIND_NOTIFICATION_LISTENER_SERVICE` (lee todas las notificaciones) y `QUERY_ALL_PACKAGES` (enumera apps instaladas) — dos indicadores clásicos de stalkerware, ausentes de `DANGEROUS_PERMISSIONS`.
- **Secretos sin patrones OpenAI/Anthropic** (`sk-...` / `sk-ant-...`) — añadidos con cuidado de que no se solapen (el patrón OpenAI exige 20+ caracteres alfanuméricos consecutivos tras `sk-`, lo que no puede matchear `sk-ant-` por el guión).
- **JWT: `weak_alg` era código muerto** — comprobaba `["hs1","rs1","none"]`, pero "hs1"/"rs1" no son algoritmos JWT reales (nunca se disparaba). Eliminado en vez de mantenerlo como falsa sensación de cobertura.
- Menor: lista de acortadores de SMS ampliada (`cutt.ly`, `bit.do`, `tiny.cc`, `shorturl.at`, `s.id`, `rb.gy`, `v.gd`, `tr.im`, `shrtco.de`, `x.co`).

7 tests de regresión nuevos (32 en total), cada uno con el escenario exacto que antes se colaba.

## Fix: falso negativo real reportado por el usuario (URL/SMS)
Mensaje real de smishing suplantando a la Seg. Social, tono burocrático ("trámite pendiente") sin urgencia agresiva, enlace a un dominio inventado (`portatsegsvcial.cfd`) sin relación textual con `seg-social.es` ni typo de 1 carácter — daba `safe`, 0/100. Tres heurísticas offline nuevas, todas reutilizables desde URLs y SMS:
- **`suspicious_tld`** (`urlModule.js`): lista de ~35 TLD desproporcionadamente abusados en phishing (`.cfd`, `.xyz`, `.top`, `.click`, `.tk`, `.gq`... — fuente: informes anuales Interisle/Spamhaus de TLDs más abusados), +30 puntos.
- **`official_notice_language`** (`smsModule.js`): frases de aviso burocrático vago (“trámite pendiente”, “consulte su información”, “gestione el trámite”) — patrón distinto de la urgencia agresiva ya cubierta, +20 puntos.
- **`brand_domain_mismatch`** (`smsModule.js`, mismo patrón que el spoof de marca de `mailModule.js` pero sobre el cuerpo del SMS): si el texto menciona una entidad conocida (`BRAND_DOMAINS` — Seg. Social, Correos, DGT, Agencia Tributaria, bancos...) y ningún enlace del mensaje apunta a su dominio real, +40 puntos. Solo se evalúa si hay al menos un enlace en el mensaje.
- Matching de palabras clave normalizado (`normalize()`: minúsculas + NFD + strip de diacríticos) para no depender de que el texto lleve tildes.

Con las tres, el mensaje reportado pasa de `safe`/0 a `dangerous`/90. Test de regresión permanente en `tests/run.js` con el texto exacto reportado, más un test de falso-positivo (mención de marca con dominio real correcto no dispara nada).

## Contraseña filtrada — Pwned Passwords (en `passwordModule.js`)
`checkPwnedPassword(pw)`: SHA-1 de la contraseña calculado en el dispositivo (`crypto.subtle.digest`), solo se envían los 5 primeros caracteres hex del hash a `api.pwnedpasswords.com/range/{prefix}` (k-anonymity — HIBP nunca ve la contraseña ni el hash completo). Botón separado, no automático por cada tecla (evita disparar red en cada pulsación mientras el usuario escribe). Verificado contra la API real: `123456` → 210M+ apariciones; contraseña random → no encontrada. No se guarda en historial, mismo motivo que el resto del módulo Contraseña.

## Share Target
`manifest.webmanifest` declara `share_target` (GET, `./index.html`, params `title`/`text`/`url`) — Cerberus aparece en el menú "Compartir" del móvil una vez instalada. `handleShareTarget()` en `app.js` lee `?text=`/`?url=` al cargar, decide destino (URL si parece `http(s)://...`, si no SMS), rellena y envía el formulario correspondiente, limpia la URL con `history.replaceState`. Probado navegando directamente con esos query params (no hay forma de simular el share sheet real del SO desde este entorno, pero la lógica de recepción es la misma sea cual sea el origen).

## DNS / SPF de dominio (`js/modules/dnsModule.js`)
Consulta DNS pública sobre HTTPS (Cloudflare `cloudflare-dns.com/dns-query`, formato JSON, confirmado con CORS abierto) para MX, TXT (SPF) y TXT de `_dmarc.dominio` (DMARC) de un dominio cualquiera — complementa Correo: en vez de solo analizar cabeceras ya recibidas, comprueba si un dominio tiene la higiene de email configurada en absoluto. Flags: sin SPF, sin DMARC, DMARC en `p=none` (detecta pero no bloquea), dominio sin resolver. Probado contra dominios reales: `google.com` (SPF+DMARC `p=reject`, safe), `example.com` (igual de estricto), dominio inventado (sin registros, dangerous). Guarda en historial como URL/Mail — es información sobre un dominio externo, no del usuario.

## Fuga WebRTC / VPN (`js/modules/webrtcModule.js`)
Único módulo que es **inherentemente de red** — no tiene modo offline, así que no lleva toggle sino un botón de acción explícita con aviso de qué contacta (`stun.l.google.com` + `api.ipify.org`). Crea un `RTCPeerConnection` con ese STUN, recoge candidatos ICE (`host` = IP local, `srflx` = IP pública vista por el STUN, filtrando alias `.local` de mDNS) y en paralelo pide la IP pública por una petición HTTPS normal (`api.ipify.org`). Si la IP vista por STUN difiere de la vista por HTTPS → flag `public_ip_leak` (STUN se salta el túnel VPN, la web ve tu IP real aunque la conexión normal muestre la de la VPN). Igual que Contraseña/JWT: **no se guarda en historial**, es información sobre el propio usuario, no un artefacto externo que analizar. Sin tests automatizados en `tests/` — mockear `RTCPeerConnection` no compensa frente a probarlo contra el STUN real, que es lo que se hizo manualmente antes de dar el módulo por bueno.

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
- Internacionalización — evaluada y aparcada, ver abajo

## Internacionalización (evaluada, no implementada)
Anotado tras medir el alcance real. **El coste está muy mal repartido entre las dos mitades**, y esa
es la razón de aparcarlo, no el tamaño total:

- **La interfaz es trabajo mecánico:** ~160 textos únicos (unos 80 en `index.html`, **52 etiquetas de
  flags** repartidas por 8 módulos, ~27 mensajes de estado/error en `app.js`). Una sesión.
- **La detección no se traduce, se reinvestiga.** `OFFICIAL_NOTICE_WORDS` está calcado del lenguaje
  de la administración española ("trámite pendiente"); un phishing alemán no dice eso. Las 21 marcas
  de `brandDomains.js` son de España (Seg. Social, DGT, Correos, AEAT, BBVA) y fuera harían falta
  Deutsche Post/Sparkasse/Finanzamt, Royal Mail/HMRC, USPS/IRS… Los `.gob.es` no tienen equivalente
  automático.

**La trampa que decide el diseño:** si se traduce solo la interfaz y se dejan las heurísticas
españolas, un angloparlante recibe una herramienta que *parece funcionar y falla en silencio* — un
smishing de Royal Mail le saldría `safe`. Eso es peor que no ofrecer el idioma, y es exactamente el
problema contra el que van las auditorías de este documento. Regla, por tanto: **un idioma solo se
ofrece si su paquete de heurísticas está hecho, no solo su UI.**

Estructura prevista si se retoma — un fichero por idioma con textos **y** datos de detección juntos,
para que sea imposible añadir un idioma a medias:

```
public/js/i18n/
  es.js      textos UI + heurísticas + marcas (España)
  en.js      textos UI + heurísticas + marcas (US/UK)
  index.js   detección con navigator.language y carga
```

Los módulos recibirían el paquete activo en vez de tener las listas hardcoded. El inglés parte con
ventaja: `URGENCY_WORDS`/`CREDENTIAL_WORDS`/`LURE_WORDS` ya son bilingües. Solo merece la pena si la
app se comparte fuera de España.

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

---

## Revisión general "no descartes nada" (2026-09-02)

Después de haberme equivocado al declarar imposible la resolución de acortadores sin backend
(la conclusión venía de pruebas con `curl` que no mandaban cabecera `Origin`, que es lo que
varios proxies CORS exigen), se repasó **cada limitación asumida**, probándola en lugar de
razonarla. Resultado: dos de ellas eran falsas, y una señal que ya existía llevaba tiempo rota.

### 1. `domain_age` no se aplicaba nunca (bug, no limitación)

`domainAge()` consultaba RDAP con el **hostname completo**. RDAP solo entiende el dominio
registrable:

```
rdap.org/domain/google.com       → 200, registro 1997-09-15
rdap.org/domain/www.google.com   → 404
```

Es decir: cualquier URL con subdominio — o sea casi todas, empezando por cualquier `www.` —
caía en `domain_age_unknown`, y `domain_new` (40 puntos, la señal más fuerte de la app después
de las listas de amenazas) **no llegaba a dispararse jamás**. Un dominio de phishing con
subdominio pasaba por "edad desconocida" en vez de "registrado hace 6 días".

Arreglado usando `registrableDomain()`, que ya existía en el mismo fichero.

### 2. Los TLD que no publican RDAP: Certificate Transparency

El bootstrap oficial de IANA (`data.iana.org/rdap/dns.json`) confirma que **`.es` y `.eu` no
tienen servidor RDAP**. Para un usuario español eso es la mitad de los dominios que le llegan.

`crt.sh` sí manda `Access-Control-Allow-Origin: *`, y el primer certificado emitido para un
dominio acota su edad por arriba. No es la fecha de registro y no se presenta como tal: la UI
dice "visto por primera vez hace N días (primer certificado)" cuando el dato viene de ahí.

Se distingue `tld_sin_rdap` (el registro no publica los datos) de `sin_datos` (la consulta
falló) mirando `res.redirected`: rdap.org redirige al servidor del registro cuando existe, así
que un 404 **sin** redirección significa que ese TLD no está en RDAP.

Coste medido y mitigado: `crt.sh` no permite limitar resultados en el servidor y un dominio
veterano devuelve megabytes (`bancosantander.es` = 2,2 MB, 14 s). Se lee en streaming con un
tope de 250 KB, y **superar el tope es en sí la respuesta**: tantísimos certificados implican
historial largo, o sea que el dominio no es reciente. Además solo se consulta si RDAP no dio
nada y el dominio no está en la lista de conocidos.

`crt.sh` throttlea con uso repetido y entonces responde sin cabeceras CORS. Se trata como
best-effort: si falla no se emite ninguna señal de sospecha.

### 3. Escalón intermedio de antigüedad

El caso real que reportó el usuario (`skypolegdansk.mom`) tenía **57 días**: pasaba el umbral
de 30 y no disparaba nada. Se añade `domain_recent` (< 180 días, 20 puntos). 20 puntos **no**
alcanzan solos el umbral de sospecha (30) — un negocio legítimo recién montado también tiene
un dominio reciente. Solo pesa acompañado de otra señal, que es justo lo que se busca.

### 4. Dos listas de dominios desincronizadas

`known-domains.json` (60 entradas) y `BRAND_DOMAINS` (59) eran fuentes separadas. Faltaban en
la comparación de typosquatting **todos los bancos españoles**, `bizum.es`, `renfe.es`,
`movistar.es` y 34 dominios más. Es el mismo fallo que ya se documentó entre `smsModule` y
`mailModule`. Se fusionan en `getKnownDomains()` para que no vuelvan a separarse.

Verificado: `bbvaa.es` / `renfee.es` / `bizumm.es` → `typosquat`; los legítimos, limpios.

### 5. Herramienta QR (capacidad que ni se había considerado)

`BarcodeDetector` es una **API del propio navegador** — soporta `qr_code` sin ninguna
librería y sin que la imagen salga del dispositivo. Se había descartado el QR asumiendo que
haría falta una dependencia; nunca se comprobó.

Un QR es el único enlace que el usuario no puede leer antes de abrirlo, que es exactamente por
lo que funciona pegar una pegatina encima del código de un parquímetro o de una multa.

Se clasifica el contenido antes de que el móvil actúe sobre él, y se delega en las
herramientas que ya existen (`checkUrl` completo si hay enlace, `checkSms` si es texto).
Señales propias del formato, que no existen en un enlace normal:

| Carga | Por qué importa |
|---|---|
| `otpauth://` | Enlaza tu 2FA con una cuenta que controla otro. Solo es legítimo si lo acabas de pedir tú |
| `javascript:` / `data:` | No es un enlace, es ejecución / contenido incrustado sin dominio que delate nada |
| `WIFI:` sin contraseña | Red abierta: quien la monta ve el tráfico no cifrado |
| `SMSTO:` con texto | SMS ya redactado: así se dan de alta suscripciones de pago |
| `tel:`/`SMSTO:` a 80x/90x | Tarificación especial, la paga quien llama |
| `bitcoin:` y similares | Solicitud de pago con importe y destinatario ya fijados |

`Safari no trae BarcodeDetector`. En vez de dejar un botón muerto, se detecta y se dice, y se
ofrece pegar el texto que la cámara del móvil ya muestra sin abrir el enlace.

Verificado extremo a extremo decodificando PNG reales, no solo la clasificación.

### Lo que se volvió a probar y sigue sin ser posible

- **Cadena salto a salto**: `unshorten.me` y `api.redirect-checker.net` siguen sin mandar
  cabeceras CORS, ahora comprobado **con** `Origin`. Sigue necesitando backend.
- **Reputación de hash de archivo**: `mb-api.abuse.ch` responde `401 Unauthorized`, ya pide
  clave. VirusTotal siempre la ha pedido.

### Estado de las suites tras los cambios

69/69 tests · 0 falsos positivos (incluidos 11 QR legítimos nuevos) · 3/27 evasiones ·
2/30 campañas · auditoría hostil sin inyección (incluidos payloads XSS por la ruta nueva de QR)


### Corrección posterior — el botón "activar y repetir" cambiaba un ajuste de privacidad

Reportado al probar la v1: el interruptor de red aparecía encendido sin haberlo activado.

No era un fallo del valor por defecto (verificado con almacenamiento limpio: apagado). Era el
botón que sale dentro de un resultado cuando el análisis fue solo offline. Decía **"Activar
comprobación en red y repetir"** y escribía la preferencia en `localStorage` de forma
**permanente y para las cuatro herramientas**. El usuario leía "repetir esta comprobación" y
se quedaba con la red encendida a partir de entonces sin haberlo decidido.

Para un ajuste que determina si los datos salen del dispositivo, eso no vale. Ahora el botón
dice **"Comprobar también en red, solo esta vez"** y hace exactamente eso: `withNetOnce()`
aplica la excepción a esa comprobación y la retira en un `finally`, sin tocar nada guardado.
El interruptor sigue siendo el único sitio donde se toma una decisión duradera.

La preferencia se saca a `public/js/netPref.js` para poder testearla sin montar la interfaz —
antes vivía suelta en `app.js`, que necesita DOM. Cuatro tests nuevos cubren: apagado por
defecto, que la excepción no se persiste, que una excepción lanzada dentro no deja la red
encendida, y que el interruptor sí persiste. `getStoredNetPref()` es lo que refleja el
interruptor (la decisión duradera), `isNetEnabled()` lo que consulta el análisis.

Los accesos a `localStorage` van con `try/catch`: en modo privado pueden lanzar, y ante la
duda lo correcto es **no** salir a la red.


### Repaso de interfaz (2026-09-02)

El contenido era correcto pero la interfaz no lo comunicaba. Cambios y por qué:

**El veredicto decía "SUSPICIOUS"** — en inglés, en una app en español, como una etiqueta de
categoría. Ahora dice qué hacer y varía según la herramienta: un enlace no se abre, un mensaje
no se responde, un archivo no se ejecuta, y un hallazgo de Secretos "hay que arreglarlo" (no es
un fraude que intente engañarte, es algo tuyo que no debería estar ahí).

`safe` sigue sin decir nunca "es seguro": dice "Sin señales de riesgo" y matiza que no ha
encontrado ninguna de las señales que sabe buscar, que no es garantía. Esa distinción es la
misma que rige todo el proyecto y no se relaja por hacer la interfaz más amable.

**El riesgo era un `60/100` suelto.** Ahora hay un anillo SVG que lo dibuja al aparecer. Es el
único movimiento de la pantalla, precisamente para que lleve la mirada al dato en vez de
competir con él.

**Todas las señales se veían iguales.** Ahora se ordenan por puntos y se sombrean por
gravedad. Las de 0 puntos (límites de la app, tipo "no se pudo resolver el destino") van al
final y apagadas: son limitaciones nuestras, no acusaciones al enlace. Para los módulos que no
publican tabla de puntos la gravedad se **hereda del veredicto** en vez de mantener una segunda
tabla en la interfaz — que es exactamente el fallo de desincronización que ya ha aparecido dos
veces en este proyecto.

**Iconos**: conjunto propio en SVG en línea. Antes eran emojis y cada sistema los dibuja a su
manera — unos planos, otros en 3D, el del QR salía como un cuadrado negro. No parecían un
conjunto.

**Sin fuentes externas.** Traer una de Google Fonts contradiría "todo corre en tu dispositivo"
y rompería el modo offline, así que se usa la pila del sistema. Es una restricción del
proyecto, no un descuido.

**Textos**: cada herramienta abre con una frase llana ("¿Ese documento.pdf es de verdad un
PDF?") y el párrafo técnico se pliega en "Qué comprueba exactamente". No se ha quitado nada.

Un bug que salió al hacerlo: `checkFile()` calculaba el riesgo solo para guardarlo en el
historial y no lo devolvía, así que el medidor pintaba un 0 al lado de "No lo abras ni lo
ejecutes". Arreglado en origen, y el medidor se omite si un módulo no da puntuación en vez de
inventar un cero.
