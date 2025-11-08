# SD-JWT Decoder with Verification

A single-file, client-side tool to **decode** Selective Disclosure JWTs (SD-JWT) and optionally **verify the issuer signature** with a supplied public key (JWK). Built with React (UMD), Babel-in-the-browser, Tailwind via CDN, and JOSE (ESM) — all loaded from CDNs; **no build step required**. 

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

## 🖥️ Live Structure

This repository consists of a single file:

```
index.html
```

It embeds:

* React 18 (UMD) + ReactDOM 18 (UMD)
* Babel standalone (transpiles the JSX in the browser)
* Tailwind CSS via CDN
* `jose@5.x` imported as an ESM module from a CDN
* The full React app in a `<script type="text/babel">` block that renders into `#root`


---

## 🚀 Quick Start

### Option A: Just open the file

1. Download `index.html`. 
2. Open it in a modern browser (Chrome/Edge/Firefox/Safari).
   *(Because all dependencies load from CDNs, file:// works in most environments. If your browser blocks module imports from a local file, use Option B.)*

### Option B: Serve locally

From the folder that contains `index.html`, run any static server, e.g.:

```bash
# Python 3
python -m http.server 8080

# Node (http-server)
npx http-server -p 8080
```

Then visit `http://localhost:8080/`. 

### Option C: Serve on Your Server

Just copy the downloaded file to your web server and access it. (Useful when you want to test an SD-JWT on a mobile phone.) 

**It is also available from https://www.sakimura.org/sd-jwt-decoder/ as well.**

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

---

## 🛠️ Development Notes

* All logic lives inside `index.html` in a React component defined in a `<script type="text/babel">` block; Babel transpiles on the fly.
* No `npm install` or bundler is necessary; dependencies load from CDNs:

  * `react`, `react-dom` (UMD),
  * `@babel/standalone`,
  * `tailwindcss` CDN,
  * `jose` (ESM). 
* If you prefer a “no-Babel-at-runtime” setup, you can migrate the JSX into a Vite/webpack project and import `jose` via npm.

---

## 🧪 Test Data

Use the built-in **Load Example** button to populate the editor with an example SD-JWT from the IETF draft and a matching example **P-256 JWK** for signature checks. The app also strips newlines so examples can be pasted directly from specs. 

---

## 📦 Deploy

Because it’s a single static file, you can host it anywhere:

* GitHub Pages
* Netlify / Vercel (static)
* Any S3/CloudFront, Cloudflare Pages, or your own server

Just serve `index.html` with typical static settings. 

---

## 🗺️ Roadmap Ideas

* Validate `_sd` digest list against disclosures (full SD-JWT verification per spec).
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
* **Primary file**: `index.html`
* **Topics**: `sd-jwt`, `jwt`, `jose`, `selective-disclosure`, `verifiable-credentials`, `react`, `tailwind`, `security-tools`
