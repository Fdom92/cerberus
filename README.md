# Cerberus

A local-first security command center — a Progressive Web App that runs in your browser with no backend, no account and no build step. Thirteen tools for the security decisions people actually face day to day: is this link safe, where does this QR code actually go, is this email spoofed, does this app want permissions it shouldn't, is my VPN actually hiding my IP.

**Try it:** **[fdom92.github.io/cerberus](https://fdom92.github.io/cerberus/)** — works in any browser, and installs to your home screen as an offline app (Add to Home Screen).

## Why

Most "security checker" tools are either a paid SaaS dashboard or a sketchy website that wants you to paste your password into a form. Cerberus is neither.

Six of the thirteen tools never touch the network at all. Five more — URLs, QR, SMS, Mail and Password — do their analysis offline and only reach out if you ask them to (one shared toggle for resolving links and checking them against threat lists, a button for the breached-password check). Only DNS/SPF and the WebRTC leak test are inherently network-bound, since there is nothing to look up otherwise. Every one of those says which service it contacts *before* it contacts it, and nothing sensitive — passwords, JWTs, scanned secrets, WebRTC results — is ever written to storage.

## Tools

| Tool | What it does | Network |
|---|---|---|
| **URLs** | Typosquatting, punycode/homograph, brand-as-subdomain and brand-in-hostname spoofing, IP-literal hosts, `@` tricks; optionally resolves the real destination behind a shortener, dates the domain (RDAP, falling back to Certificate Transparency for TLDs like `.es` that publish no RDAP) and looks it up against Cloudflare's phishing/malware lists | Offline by default, opt-in |
| **QR** | Decodes a photographed QR with the browser's own `BarcodeDetector` — no library, the image never leaves the device — and shows exactly what it contains before the phone acts on it. Classifies the payload (link, wifi, `otpauth:` 2FA enrolment, prefilled SMS, premium-rate number, payment request, `javascript:`) and hands any embedded link to the URL analysis | Offline, opt-in for the link |
| **Mail** | SPF/DKIM/DMARC parsing, From/Return-Path/Reply-To mismatches, brand impersonation in the display name and Subject, analysis of links in the body; optional threat-list lookup | Offline, opt-in threat lookup |
| **SMS** | Smishing heuristics — urgency language, credential requests, brand/domain mismatch, callback-number scams, embedded shortened or suspicious links; optional threat-list lookup on the linked domains | Offline, opt-in threat lookup |
| **DNS / SPF** | Looks up a domain's MX, SPF and DMARC records to see whether it's protected against being spoofed | Network (Cloudflare DoH) |
| **Files** | Magic-byte signature detection vs. declared extension, SHA-256, Shannon entropy (flags packed/encrypted executables) | Offline |
| **EXIF** | Reads JPEG metadata — camera, timestamp, and GPS coordinates before you share a photo | Offline |
| **Decoder** | Base64 / Base64url / Hex / URL-decode, tries all four on pasted text | Offline |
| **Secrets** | Regex scanner for AWS/GitHub/GitLab/Slack/Stripe/Google/Twilio/SendGrid/Mailgun/npm/OpenAI/Anthropic keys and private-key blocks in pasted code | Offline |
| **Apps** | APK (`AndroidManifest.xml`) and IPA (`Info.plist`) parsed from raw ZIP bytes — declared package, dangerous permissions, plus a binary string/secret scan on any file | Offline |
| **Password** | Entropy estimate, common-password list, sequence/repeat detection — never persisted. Optional breach check sends only the first 5 characters of the password's SHA-1 (k-anonymity), never the password | Offline, opt-in breach check |
| **JWT** | Decodes header/payload, flags `alg:none`, expiry, missing `exp` — no signature verification, never persisted | Offline |
| **WebRTC leak** | Detects whether your browser leaks your real IP past a VPN via STUN | Network (explicit action, disclosed) |

History (IndexedDB, on-device only) records completed checks — except Password, JWT, and WebRTC, which touch identity/credential data and are never written to storage.

## Interface

The verdict is the part most people will read, so it says what to *do* — "No lo abras", "Desconfía de este mensaje" — rather than naming a category, and it never says "safe" in the sense of *is safe*: what it reports is that none of the signals it knows how to look for were found, which is a different claim. A ring gauge carries the magnitude, since a bare `60/100` means nothing to someone who does not work in this. Findings are sorted by weight and shaded by it, so "this domain is on Cloudflare's phishing list" (80 points) no longer looks identical to "the TLD is a cheap one" (15).

Each tool leads with a plain-language sentence and folds the technical description into a "Qué comprueba exactamente" disclosure — nothing was removed, it was reordered.

Icons are a hand-drawn inline SVG set rather than emoji, which every platform renders in its own style. There are no webfonts: pulling one from a CDN would contradict "everything runs on your device" and break offline use, so the type is a system stack.

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
    modules/                one file per tool (checkUrl, checkQr, checkMail, checkApp, ...)
  manifest.webmanifest, sw.js, icons/    PWA install + offline cache
```

`zipReader.js`, `axmlParser.js`, and `plistParser.js` are written from scratch against the public format specs — no `jszip` or similar, since a "runs anywhere, low footprint" PWA is the whole point. Decompression uses the browser's native `DecompressionStream`.

## Getting started

No install, no build:

```bash
python3 -m http.server 8080 --directory public
```

Open `http://localhost:8080`. Every tool works offline from there; the URL, SMS, Mail, Password, DNS and WebRTC tools need real network access for their opt-in checks.

## Testing

`tests/` is a zero-dependency regression suite: `tests/run.js` (69 tests) imports the real modules from `public/js/` and exercises them against hand-built synthetic fixtures (a JPEG with EXIF/GPS, a ZIP with stored and deflated entries, an AndroidManifest.xml, a binary plist — all constructed byte-by-byte in `tests/fixtures.js`, not mocked).

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080/tests/index.html`. Pass/fail renders on the page and logs to the console.

A fifth suite at `tests/campaign-audit.html` runs 30 complete, realistic phishing campaigns as they actually arrive in Spain (Correos customs fees, bank account suspensions, DGT fines, fake Bizum transfers, the "hi mum, this is my new number" scam, CEO fraud, malware in ZIPs and ISOs), tested in the **default** configuration with network checks off. The first run had 9 of 30 coming back clean.

A fourth suite at `tests/evasion-audit.html` is the red team: 27 real attacks built specifically to slip past each heuristic (brand as a subdomain of the attacker's domain, double extensions, zero-width characters inside keywords, a brand named only in the Subject). The first run had 18 of 27 coming back clean; three remain, each documented as a deliberate limit rather than an oversight.

A third suite at `tests/hostile-audit.html` throws XSS payloads, malformed input, empty files and a tampered APK at every module, and checks two things: that nothing injects into the DOM, and that nothing throws an internal browser error into the UI.

There's a second suite at `tests/fp-audit.html` that runs the opposite check: a corpus of **legitimate** real-world inputs (2FA codes, accented domains, newsletters sent through Mailchimp, compressed installers, documentation placeholders) that must **not** be flagged. A security tool that cries wolf at ordinary things teaches people to ignore it, which is worse than having no tool — so this suite is treated as seriously as the detection tests. It prints a table of anything that trips, rather than pass/fail.

## Deploying

Any static host works — `public/` is the whole site, with nothing to build.

This repo deploys to GitHub Pages through [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml), which uploads `public/` on every push to `main`. It needs **Settings → Pages → Source: GitHub Actions** (not "Deploy from a branch" — the branch source can only publish the repo root or `/docs`, so it would serve this README through Jekyll instead of the app).

`manifest.webmanifest` and `sw.js` do the rest: once it's on HTTPS, the browser offers Add to Home Screen and the app works offline from then on.

## License

MIT — see [LICENSE](LICENSE).

## Design notes

Longer write-ups of specific decisions — why a CORS-proxy opt-in instead of a backend, why threat-list hits count but misses never reassure, how the AXML/plist parsers were validated — live in [`docs/superpowers/specs/`](docs/superpowers/specs/).
