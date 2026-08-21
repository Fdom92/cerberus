const CACHE = "cerberus-v8";
const SHELL = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./css/style.css",
  "./js/app.js",
  "./js/db.js",
  "./js/magicBytes.js",
  "./js/brandDomains.js",
  "./js/textHeuristics.js",
  "./js/zipReader.js",
  "./js/axmlParser.js",
  "./js/plistParser.js",
  "./js/sampleData.js",
  "./js/modules/urlModule.js",
  "./js/modules/fileModule.js",
  "./js/modules/historyModule.js",
  "./js/modules/mailModule.js",
  "./js/modules/smsModule.js",
  "./js/modules/jwtModule.js",
  "./js/modules/passwordModule.js",
  "./js/modules/decodeModule.js",
  "./js/modules/exifModule.js",
  "./js/modules/secretsModule.js",
  "./js/modules/appsModule.js",
  "./js/modules/webrtcModule.js",
  "./js/modules/dnsModule.js",
  "./data/known-domains.json",
  "./icons/icon.svg",
  "./icons/icon-180.png",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== location.origin) return; // never intercept the opt-in network calls (proxy/RDAP)
  if (event.request.method !== "GET") return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((res) => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(CACHE).then((cache) => cache.put(event.request, clone));
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
