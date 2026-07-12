# SD-JWT Decoder with Verification

This project is a **purely client-side SD-JWT inspection tool** built with **Vite + React + Tailwind CSS v4**.

It decodes Selective Disclosure JWTs (SD-JWT) and can optionally verify the issuer
signature using a supplied public key (JWK), **entirely in the browser**.

**No runtime Babel, no CDN dependencies, and compatible with a strict Content Security Policy (CSP).**

---

## ✨ Features

* Paste an **SD-JWT** in the common `JWT~disclosure~disclosure~...` format; newlines/whitespace are auto-cleaned. 
* Instant **JWT header/payload** decode and pretty-print panels with one-click **Copy**. 
* Parses and lists **disclosures**, showing raw Base64URL and decoded tuples `[salt, claimName, claimValue]`. 
* **SD digest verification** (sha-256): recomputes each disclosure's digest and checks it against the payload's `_sd` anchors — including nested anchors and digests embedded in other disclosures (recursive disclosures). **Duplicate digests are detected and flagged as a spec violation.**
* Builds **Reconstructed Claims** by applying **only digest-verified** disclosures over the original payload (excludes `_sd`, `_sd_alg`); disclosures that fail the digest check are listed but never merged. 
* Optional **signature verification** using **JOSE** with a provided **public key (JWK)**; the permitted algorithms are **derived from the key** (never from the attacker-controlled JWT header) to prevent algorithm-confusion attacks. 
* **Key Binding JWT (KB-JWT) verification** when present: checks `typ` is `kb+jwt`, recomputes and compares `sd_hash` over the presented SD-JWT, and verifies the holder signature against `cnf.jwk`. 
* **Load Example** SD-JWT and **Load Example Key** buttons included for quick testing (from the IETF draft example). 
* Clean, responsive UI with Tailwind; inline SVG icons (Lucide-style) – **no external icon package required**. 

---

## 🖥️ Project Structure

The project is built as a small Vite application and outputs static assets for deployment.
```bash
.
├── index.html # Vite HTML entry
├── src/
│ ├── main.jsx # React bootstrap
│ ├── App.jsx # SD-JWT decoder UI (React component)
│ ├── sdjwt.js # SD-JWT parsing/verification logic (pure, unit-tested)
│ ├── sdjwt.test.js # Vitest unit tests for sdjwt.js
│ └── index.css # Tailwind CSS entry
├── tailwind.config.js
├── postcss.config.cjs
├── vite.config.js
└── dist/ # Production build output (generated)
```
All dependencies are resolved at build time via npm.
The production output (`dist/`) contains only static HTML/CSS/JS.


---

## 🚀 Quick Start (Development)

### Prerequisites
- Node.js 18+ (recommended)

### Install dependencies
```bash
npm install
```
### Run development server
```bash
npm run dev
```
Then open: 
```bash
http://localhost:5173/
```
### Run tests
```bash
npm test
```
Unit tests (Vitest) cover the SD-JWT logic in `src/sdjwt.js`: digest verification
(including forged/duplicate/recursive disclosures), the key-derived algorithm
allowlist, issuer signature verification, KB-JWT verification, parsing, and
prototype-pollution guards.

### Production build
```bash
npm run build
```
The static output is generated in `dist/`. 


---

## 🧩 Usage

1. **Paste SD-JWT** into **“SD-JWT Input”**. Newlines and spaces are automatically stripped so you can paste directly from specs.
2. Click **Decode SD-JWT** to view:

   * **JWT Header**
   * **JWT Payload (Original)**
   * **Disclosures** (raw + decoded)
   * **SD Digest Verification** (matched / missing / extra / duplicate digests)
   * **Reconstructed Claims** (payload with digest-verified disclosed values applied)
   * **KB-JWT** (if detected, with `typ` / `sd_hash` / holder-signature checks)
3. (Optional) **Verify Signature**:

   * Paste the **issuer’s public key (JWK)** into **“Issuer Public Key (JWK format)”**.
   * Click **Verify Signature** to validate using JOSE; the UI reports success/failure and algorithm.
     All of the above flows and panels are implemented in the single HTML file’s React component. 

---

## 🔍 How It Works (High-level)

* **Parsing**: Splits on `~` to separate the signed JWT from disclosures and an optional KB-JWT (only the **last** segment can be a KB-JWT, per spec); handles whitespace/newlines; decoding is UTF-8 safe. 
* **Decoding**: Base64URL-decodes header/payload; disclosures are decoded and displayed; tuples are interpreted as `[salt, claimName, claimValue]`. 
* **Digest verification**: Computes `SHA-256(base64url(disclosure))` for every disclosure and matches it against all digest anchors (`_sd` arrays and `"..."` values) found in the payload **and** inside other disclosures; reports matched / missing / extra / duplicate digests. 
* **Reconstruction**: Starts from the original payload, applies `claimName=claimValue` **only for digest-verified disclosures** (with prototype-pollution guards), and removes `_sd` / `_sd_alg` for a clean view. 
* **Signature verification**: Parses the provided JWK, derives the set of permitted algorithms from its `kty`/`crv`/`alg` (symmetric `oct` keys are rejected), requires the JWT header `alg` to be in that set, then verifies with JOSE restricted to that allowlist. 
* **KB-JWT verification**: Checks the `kb+jwt` header type, recomputes `sd_hash` over the presentation (issuer JWT + disclosures + trailing `~`), and verifies the signature with the holder key from the issuer payload's `cnf.jwk` using the same key-derived algorithm allowlist. 
* **UI**: Tailwind components and inline SVG icons; React state tracks decode/verify results and copy feedback. 

---

## ⚖️ Security, Scope & Limitations

* **Client-side only**: No data leaves the browser; everything happens locally. 
* **Signature verification** verifies the **JWT signature** with your supplied **public key (JWK)**.

  * This tool **does not** fetch keys from JWKS endpoints and **does not** perform issuer/audience validations (JOSE's `exp`/`nbf` checks do apply when those claims are present).
* **Algorithm handling**: The permitted algorithms are **derived from the supplied JWK** (`kty`/`crv`/`alg`), never from the JWT header, preventing algorithm-confusion / key-type-confusion attacks. Symmetric (`oct`) keys are rejected. 
* **SD digest verification**: `_sd` hash binding **is** recomputed and validated (sha-256 only; other `_sd_alg` values are reported as unsupported). Duplicate digests fail verification, as required by the spec. Only digest-verified disclosures are merged into "Reconstructed Claims" — forged disclosures appended to a signed SD-JWT are flagged and excluded. 
* **KB-JWT**: `typ`, `sd_hash` binding, and the holder signature (via `cnf.jwk`) **are** verified. Note that `cnf.jwk` is read from the issuer JWT payload, so the KB-JWT result is only meaningful if the **issuer signature verification also succeeded**. `aud`/`nonce` freshness is **not** checked (the tool has no verifier context). 
* **Reconstruction is flat**: Disclosed claims are applied at the top level for inspection; nested claims are not re-inserted at their exact structural position as a spec-compliant verifier would. 
* Intended as a **developer/educational tool**; please review and extend before using in security-critical workflows.

### Content Security Policy

The application is intentionally designed to run under a strict CSP.

- No external scripts or styles
- No inline script execution
- No `unsafe-eval`

This makes it suitable for deployment alongside security-sensitive sites.


---

## 🛠️ Development Notes

- This project uses **Vite + React** with JSX compiled at build time.
- There is **no runtime transpilation** (no `@babel/standalone`).
- All JavaScript and CSS assets are self-hosted.
- `jose` is imported as an npm dependency and bundled during build.
- The application is compatible with **CSP without `unsafe-eval` or external script sources**.

---

## 🧪 Test Data

Use the built-in **Load Example** button to populate the editor with an example SD-JWT from the IETF draft and a matching example **P-256 JWK** for signature checks. The app also strips newlines so examples can be pasted directly from specs. 

---


## 📦 Deploy

This project builds to a fully static site.

Deploy the contents of `dist/` to any static hosting environment:

- Apache / nginx
- GitHub Pages
- Netlify / Vercel
- S3 + CloudFront
- Cloudflare Pages

The application is designed to work with a **strict Content Security Policy** such as:

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self';
  font-src 'self';
  object-src 'none';
  base-uri 'none';
  form-action 'none';
  frame-ancestors 'none'
```

### Apache deployment with `.htaccess` (recommended)

The repository ships [`public/.htaccess`](public/.htaccess), which sets the CSP above plus
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and
`Cross-Origin-Opener-Policy`. Vite copies it into `dist/` on every build, so simply
deploying the contents of `dist/` to Apache enables the headers.

**Why `.htaccess` instead of a `<meta http-equiv>` tag:** a CSP meta tag would also apply to
the Vite **dev server**, whose HMR client injects inline scripts and would be blocked. Setting
the policy at the web-server layer keeps development unaffected while fully protecting the
deployed site (and allows directives like `frame-ancestors` that meta tags cannot express).

Steps / caveats:

1. Build (`npm run build`) and deploy the contents of `dist/` — including the (hidden)
   `.htaccess` file; make sure your copy method doesn't skip dotfiles (`rsync -a` is fine,
   a bare `cp *` is not).
2. Apache must have **`mod_headers` enabled**. The directives are wrapped in
   `<IfModule mod_headers.c>`, so a server without it serves the site **silently without
   the security headers** — verify with
   `curl -sI https://your-host/sd-jwt-decoder/ | grep -i content-security-policy`.
3. The directory (or a parent) needs **`AllowOverride`** permitting `.htaccess` header
   directives (e.g. `AllowOverride All` or at least `FileInfo`). With `AllowOverride None`
   the file is ignored — in that case move the `Header always set ...` lines verbatim into
   the vhost/directory config instead.
4. **Serve over HTTPS** (or localhost): the digest and signature checks use
   `crypto.subtle`, which browsers only expose in secure contexts. On plain HTTP the
   decoder works but verification fails with a SubtleCrypto error.
5. `vite.config.js` uses `base: "./"`, so serving from a subdirectory
   (e.g. `/sd-jwt-decoder/`) works out of the box; the `.htaccess` applies to that
   directory tree only.

For non-Apache hosts (nginx, Netlify, Cloudflare Pages, S3/CloudFront), `.htaccess` is
ignored — set the same headers with that platform's mechanism (`add_header`, `_headers`
file, response-header policies, etc.).

---

## 🗺️ Roadmap Ideas

* Support `_sd_alg` values beyond sha-256 (sha-384/sha-512).
* Spec-compliant nested reconstruction (re-insert disclosed claims at their exact structural position).
* Support JWKS discovery (`kid`) and issuer metadata resolution.
* Optional claims validation (iss/aud) and KB-JWT `aud`/`nonce` checks.
* UI: file import/export, JSON download of decoded artifacts.
* Additional JOSE algs and error details.
  (These are straightforward to add within the current structure.) 

---

## 🤝 Acknowledgements

* Example SD-JWT and example JWK flow reference the IETF OAuth SD-JWT draft specification; see the **About** section and example link referenced in the UI. 

---

## 📄 License

MIT License.

---
* Build system: Vite
* UI: React + Tailwind CSS v4
* Crypto: jose
* **Topics**: `sd-jwt`, `jwt`, `jose`, `selective-disclosure`, `verifiable-credentials`, `react`, `tailwind`, `security-tools`
