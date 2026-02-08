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
* Builds **Reconstructed Claims** by applying disclosed values over the original payload (excludes `_sd`, `_sd_alg`). 
* Optional **signature verification** using **JOSE** with a provided **public key (JWK)**; shows algorithm and result. 
* Detects and decodes an optional **Key Binding JWT (KB-JWT)** when present. 
* **Load Example** SD-JWT and **Load Example Key** buttons included for quick testing (from the IETF draft example). 
* Clean, responsive UI with Tailwind; inline SVG icons (Lucide-style) – **no external icon package required**. 

---

## 🖥️ Project Structure

The project is built as a small Vite application and outputs static assets for deployment.

.
├── index.html # Vite HTML entry
├── src/
│ ├── main.jsx # React bootstrap
│ ├── App.jsx # SD-JWT decoder UI and logic
│ └── index.css # Tailwind CSS entry
├── tailwind.config.js
├── postcss.config.cjs
├── vite.config.js
└── dist/ # Production build output (generated)

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
http://localhost:5273/
```
### Production build
```bash
npm run build
```
The static output is generated in `dist/'. 


---

## 🧩 Usage

1. **Paste SD-JWT** into **“SD-JWT Input”**. Newlines and spaces are automatically stripped so you can paste directly from specs.
2. Click **Decode SD-JWT** to view:

   * **JWT Header**
   * **JWT Payload (Original)**
   * **Disclosures** (raw + decoded)
   * **Reconstructed Claims** (payload with disclosed values applied)
   * **KB-JWT** (if detected)
3. (Optional) **Verify Signature**:

   * Paste the **issuer’s public key (JWK)** into **“Issuer Public Key (JWK format)”**.
   * Click **Verify Signature** to validate using JOSE; the UI reports success/failure and algorithm.
     All of the above flows and panels are implemented in the single HTML file’s React component. 

---

## 🔍 How It Works (High-level)

* **Parsing**: Splits on `~` to separate the signed JWT from disclosures and an optional KB-JWT; handles whitespace/newlines. 
* **Decoding**: Base64URL-decodes header/payload; disclosures are decoded and displayed; tuples are interpreted as `[salt, claimName, claimValue]`. 
* **Reconstruction**: Starts from the original payload, applies disclosed `claimName=claimValue`, and then removes `_sd` and `_sd_alg` for a clean view. 
* **Verification**: Imports the provided JWK with JOSE, then verifies the JWT using the algorithm from the protected header (restricted via `algorithms: [alg]`). 
* **UI**: Tailwind components and inline SVG icons; React state tracks decode/verify results and copy feedback. 

---

## ⚖️ Security, Scope & Limitations

* **Client-side only**: No data leaves the browser; everything happens locally. 
* **Signature verification** verifies the **JWT signature** with your supplied **public key (JWK)**.

  * This tool **does not** fetch keys from JWKS endpoints and **does not** perform issuer/audience/time validations beyond JOSE’s signature check.
  * It also **does not** currently recompute and validate `_sd` digests against disclosures (i.e., full SD-JWT hash-binding verification). The “Reconstructed Claims” are for inspection/education. 
* **Algorithm handling**: The implementation imports the JWK and restricts verification to the algorithm advertised in the JWT header. Review before production use. 
* **KB-JWT**: Decoded and displayed when present; cryptographic binding validation beyond basic decode is **not** implemented. 
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
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none'
```
---

## 🗺️ Roadmap Ideas

* Validate `_sd` digest list against disclosures (full SD-JWT verification per spec) beyond sha-256
* Support JWKS discovery (`kid`) and issuer metadata resolution.
* Optional claims/time validation (iss/aud/exp/nbf).
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
