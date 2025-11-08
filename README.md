# SD-JWT Decoder

Single-page web tool for decoding and verifying SD-JWT tokens directly in your browser.

***

### Overview

This project is a standalone HTML page that decodes and cryptographically verifies SD-JWT (Selective Disclosure JWT) tokens. It works entirely client-side, requiring no backend server or external API.  
You can inspect each disclosed claim, verify the digital signature, and view the reconstructed credential payload visually.

***

### Features

- Parse and display header, payload, and disclosed claims of SD-JWTs  
- Verify signature against the issuer’s public key  
- Support for compact serialization  
- Offline-capable (no data sent to external servers)  
- Clean, minimal UI for direct browser use  

***

### Usage

1. Clone this repository or download the single HTML file:
   ```bash
   git clone https://github.com/<your-username>/sd-jwt-decoder.git
   ```
2. Open the `sd-jwt-decoder.html` file in any modern browser.  
3. Paste your SD-JWT and optional disclosure bundles in the input area.  
4. Provide the issuer’s public key (JWK format).  
5. Click **Decode** to inspect and validate the result. (You can independently verify by clicking **Verify** button as well.)   

***

### Technical Notes

- All cryptographic operations are handled locally.  
- No dependencies or build tools are required—everything runs as-is in the browser.  
- Intended for demonstration, debugging, and educational use; not for production. I wrote it to proof-read the IETF sd-jwt-vc draft before the last call. 

***

### Example

For testing, you can use sample SD-JWTs from public specifications or conformance suites (e.g., IETF drafts).

***

### License

MIT License

***
