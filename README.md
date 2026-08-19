# Cerberus

A local-first security command center — a Progressive Web App that runs entirely in your browser, no backend, no account, no build step. Ten tools for the security decisions people actually face day to day: is this link safe, is this email spoofed, does this app want permissions it shouldn't, is my VPN actually hiding my IP.

**Try it:** [live demo](https://claude.ai/code/artifact/333a8f3b-1d63-4850-8698-de06063a0d85) (single-file build, no install needed) — or deploy `public/` yourself for the full installable PWA (see [Deploying](#deploying)).

## Why

Most "security checker" tools are either a paid SaaS dashboard or a sketchy website that wants you to paste your password into a form. Cerberus is neither: everything runs on-device, the two features that genuinely need the network are opt-in and disclosed before the first request, and nothing sensitive (passwords, JWTs, scanned secrets) ever touches storage.

## Tools

| Tool | What it does | Network |
|---|---|---|
| **URLs** | Typosquatting, punycode/homograph, IP-literal hosts, `@` tricks; optional redirect resolution + domain-age (RDAP) | Offline by default, opt-in |
| **Mail** | SPF/DKIM/DMARC parsing, From/Return-Path/Reply-To mismatches, brand impersonation | Offline |
| **SMS** | Smishing heuristics — urgency language, credential requests, embedded shortened/suspicious links | Offline |
| **Files** | Magic-byte signature detection vs. declared extension, SHA-256, Shannon entropy (flags packed/encrypted executables) | Offline |
| **EXIF** | Reads JPEG metadata — camera, timestamp, and GPS coordinates before you share a photo | Offline |
| **Decoder** | Base64 / Base64url / Hex / URL-decode, tries all four on pasted text | Offline |
| **Secrets** | Regex scanner for AWS/GitHub/GitLab/Slack/Stripe/Google/Twilio/SendGrid/Mailgun/npm keys and private-key blocks in pasted code | Offline |
| **Apps** | APK (`AndroidManifest.xml`) and IPA (`Info.plist`) parsed from raw ZIP bytes — declared package, dangerous permissions, plus a binary string/secret scan on any file | Offline |
| **Password** | Entropy estimate, common-password list, sequence/repeat detection — never persisted | Offline |
| **JWT** | Decodes header/payload, flags `alg:none`, expiry, missing `exp` — no signature verification, never persisted | Offline |
| **WebRTC leak** | Detects whether your browser leaks your real IP past a VPN via STUN | Network (explicit action, disclosed) |

History (IndexedDB, on-device only) records completed checks — except Password, JWT, and WebRTC, which touch identity/credential data and are never written to storage.

## Architecture

Vanilla HTML/CSS/JS, ES modules, zero dependencies, zero build step. `public/` is the entire deployable app:

```
public/
  index.html          shell: home grid + one <section> per tool
  css/style.css        dark-first, light-mode via prefers-color-scheme
  js/
    app.js              wiring: nav, forms, rendering
    db.js               IndexedDB wrapper (localStorage fallback)
    magicBytes.js        file signature table + hashing/entropy
    zipReader.js          hand-rolled ZIP central-directory reader
    axmlParser.js          Android Binary XML parser (AndroidManifest.xml)
    plistParser.js          binary + XML plist parser (iOS Info.plist)
    sampleData.js            in-browser generators for the "try it" buttons
    modules/                one file per tool (checkUrl, checkMail, checkApp, ...)
  manifest.webmanifest, sw.js, icons/    PWA install + offline cache
```

`zipReader.js`, `axmlParser.js`, and `plistParser.js` are written from scratch against the public format specs — no `jszip` or similar, since a "runs anywhere, low footprint" PWA is the whole point. Decompression uses the browser's native `DecompressionStream`.

## Getting started

No install, no build:

```bash
python3 -m http.server 8080 --directory public
```

Open `http://localhost:8080`. Every tool works offline from there; the URL and WebRTC tools need real network access for their opt-in checks.

## Testing

`tests/` is a zero-dependency regression suite: `tests/run.js` imports the real modules from `public/js/` and exercises them against hand-built synthetic fixtures (a JPEG with EXIF/GPS, a ZIP with stored and deflated entries, an AndroidManifest.xml, a binary plist — all constructed byte-by-byte in `tests/fixtures.js`, not mocked).

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080/tests/index.html`. Pass/fail renders on the page and logs to the console.

## Deploying

Any static host works. For GitHub Pages: **Settings → Pages → Source: Deploy from a branch → `main` / `/public`**. That's it — `manifest.webmanifest` and `sw.js` make it installable (Add to Home Screen) and usable offline from there.

## Design notes

Longer write-ups of specific decisions — why a CORS-proxy opt-in instead of a backend, why the typosquat distance threshold is 1 not 2, how the AXML/plist parsers were validated — live in [`docs/superpowers/specs/`](docs/superpowers/specs/).
