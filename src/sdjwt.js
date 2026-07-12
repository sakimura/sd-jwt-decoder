import { importJWK, jwtVerify } from "jose";

// Pure SD-JWT parsing and verification logic, kept free of React/DOM so it
// can be unit-tested directly (see sdjwt.test.js).

// --- base64url helpers ---

export const base64UrlToBytes = (b64url) => {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const str = atob(b64);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
};

export const bytesToBase64Url = (bytes) => {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

export const base64UrlDecode = (str) => {
  // Decode via bytes + TextDecoder so non-ASCII (UTF-8) claim values survive
  const text = new TextDecoder("utf-8").decode(base64UrlToBytes(str));
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

// --- SD-JWT _sd digest verification ---

// _sd_alg values supported for digest computation (IANA hash names → SubtleCrypto)
export const HASH_ALGS = {
  "sha-256": "SHA-256",
  "sha-384": "SHA-384",
  "sha-512": "SHA-512",
};

export const hashB64Url = async (sdAlg, bytes) => {
  const subtleAlg = HASH_ALGS[sdAlg];
  if (!subtleAlg) throw new Error(`Unsupported _sd_alg "${sdAlg}"`);
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto SubtleCrypto unavailable (use HTTPS or localhost).");
  const digest = await crypto.subtle.digest(subtleAlg, bytes);
  return bytesToBase64Url(new Uint8Array(digest));
};

export const sha256B64Url = (bytes) => hashB64Url("sha-256", bytes);

// Digest over UTF-8 of the BASE64URL disclosure string per SD-JWT spec
export const digestDisclosureB64Url = async (disclosureB64Url, sdAlg = "sha-256") =>
  hashB64Url(sdAlg, new TextEncoder().encode(disclosureB64Url));

// Recursively collect digest anchors:
//  - any array under key "_sd"
//  - any object's "..." value
export const collectAllDigests = (node, acc = []) => {
  if (Array.isArray(node)) {
    for (const item of node) collectAllDigests(item, acc);
  } else if (node && typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (k === "_sd" && Array.isArray(v)) {
        for (const d of v) if (typeof d === "string") acc.push(d);
      } else if (k === "..." && typeof v === "string") {
        acc.push(v);
      }
      collectAllDigests(v, acc);
    }
  }
  return acc;
};

export const verifySdListAgainstDisclosures = async (payload, disclosures) => {
  const sdAlg = (payload?._sd_alg || "sha-256").toLowerCase();
  // Digest anchors live in the payload AND inside disclosure values
  // (recursive disclosures per the SD-JWT spec), so collect from both.
  const anchorList = collectAllDigests(payload);
  for (const d of disclosures) collectAllDigests(d.decoded, anchorList);
  const allDigests = new Set(anchorList);
  if (!HASH_ALGS[sdAlg]) {
    return { ok: false, alg: sdAlg, reason: "Unsupported _sd_alg", matches: [], missing: [], extra: Array.from(allDigests), duplicates: [] };
  }
  const computed = await Promise.all(
    disclosures.map(async (d) => ({ disclosure: d.raw, digest: await digestDisclosureB64Url(d.raw, sdAlg) }))
  );
  const matches = [];
  const missing = [];
  for (const c of computed) {
    if (allDigests.has(c.digest)) matches.push(c);
    else missing.push(c);
  }
  const computedDigests = new Set(computed.map((c) => c.digest));
  const extra = Array.from(allDigests).filter((d) => !computedDigests.has(d));
  // The spec requires rejecting an SD-JWT if any digest appears more than
  // once among the anchors, or if two disclosures yield the same digest.
  const dupAnchors = anchorList.filter((d, i) => anchorList.indexOf(d) !== i);
  const digestCounts = new Map();
  for (const c of computed) digestCounts.set(c.digest, (digestCounts.get(c.digest) || 0) + 1);
  const dupDisclosures = Array.from(digestCounts).filter(([, n]) => n > 1).map(([d]) => d);
  const duplicates = Array.from(new Set([...dupAnchors, ...dupDisclosures]));
  const ok = missing.length === 0 && duplicates.length === 0;
  return { ok, alg: sdAlg, matches, missing, extra, duplicates, totalSd: allDigests.size, disclosed: computed.length };
};

// --- claim reconstruction ---

const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);

export function safeSetClaim(obj, key, value) {
  if (typeof key !== "string") return;
  if (DANGEROUS_KEYS.has(key)) return;
  obj[key] = value;
}

// Spec-compliant nested reconstruction: walks the payload, re-inserting each
// digest-verified disclosure at its exact structural position — object `_sd`
// digests become `name: value` members of that object, and array elements of
// the form `{"...": digest}` are replaced by the disclosed value (or dropped
// when undisclosed). Disclosed values are processed recursively, so recursive
// disclosures unfold too. `matchedByDigest` maps digest → disclosure and must
// contain only digest-verified disclosures, so forged disclosures appended to
// a signed SD-JWT are never merged.
export const reconstructClaims = (payload, matchedByDigest) => {
  const processNode = (node) => {
    if (Array.isArray(node)) {
      const out = [];
      for (const item of node) {
        if (item && typeof item === "object" && !Array.isArray(item) && typeof item["..."] === "string") {
          const disc = matchedByDigest.get(item["..."]);
          // Array element disclosures are 2-element [salt, value]
          if (disc && Array.isArray(disc.decoded) && disc.decoded.length === 2) {
            out.push(processNode(disc.decoded[1]));
          }
          // undisclosed array elements are omitted, per spec
        } else {
          out.push(processNode(item));
        }
      }
      return out;
    }
    if (node && typeof node === "object") {
      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (k === "_sd" || k === "_sd_alg") continue;
        safeSetClaim(out, k, processNode(v));
      }
      if (Array.isArray(node._sd)) {
        for (const digest of node._sd) {
          const disc = matchedByDigest.get(digest);
          // Object property disclosures are 3-element [salt, name, value]
          if (disc && Array.isArray(disc.decoded) && disc.decoded.length === 3) {
            const [, claimName, claimValue] = disc.decoded;
            safeSetClaim(out, claimName, processNode(claimValue));
          }
        }
      }
      return out;
    }
    return node;
  };
  return processNode(payload);
};

// --- parsing ---

export const parseSdJwt = (input) => {
  // Remove all newlines and whitespace to handle multi-line input from spec documents
  const cleaned = input.replace(/[\r\n\s]/g, "");
  const parts = cleaned.trim().split("~");
  const jwtString = parts[0];
  const jwtParts = jwtString.split(".");
  if (jwtParts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  const header = base64UrlDecode(jwtParts[0]);
  const payload = base64UrlDecode(jwtParts[1]);
  const signature = jwtParts[2];

  const disclosures = [];
  let kbJwt = null;
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;
    // Per the SD-JWT spec, a Key Binding JWT can only be the last element
    // (disclosures are dot-free base64url, so a dotted segment anywhere
    // else is malformed rather than a KB-JWT).
    if (i === parts.length - 1 && part.split(".").length === 3) {
      const kbParts = part.split(".");
      kbJwt = {
        raw: part,
        header: base64UrlDecode(kbParts[0]),
        payload: base64UrlDecode(kbParts[1]),
        signature: kbParts[2],
      };
    } else {
      try {
        disclosures.push({ raw: part, decoded: base64UrlDecode(part) });
      } catch {
        console.warn("Failed to decode disclosure:", part);
      }
    }
  }
  // The presentation a KB-JWT's sd_hash covers: everything up to and
  // including the last "~" before the KB-JWT.
  const presentation = kbJwt ? parts.slice(0, -1).join("~") + "~" : null;
  return { jwtString, header, payload, signature, disclosures, kbJwt, presentation };
};

// --- signature verification ---

// Allowed signature algorithms are derived from the *key*, never from the
// attacker-controlled JWT header, to prevent algorithm-confusion attacks.
export const ASYMMETRIC_ALGS = new Set([
  "ES256", "ES384", "ES512", "ES256K",
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "EdDSA", "Ed25519", "Ed448",
]);

export const allowedAlgsForJwk = (jwk) => {
  if (!jwk || typeof jwk !== "object") throw new Error("Public key must be a JWK object");
  if (jwk.kty === "oct") throw new Error("Symmetric (oct) keys are not accepted for issuer signature verification");
  if (jwk.alg) {
    if (!ASYMMETRIC_ALGS.has(jwk.alg)) throw new Error(`Key algorithm ${jwk.alg} is not an accepted asymmetric signature algorithm`);
    return [jwk.alg];
  }
  switch (jwk.kty) {
    case "EC":
      switch (jwk.crv) {
        case "P-256": return ["ES256"];
        case "P-384": return ["ES384"];
        case "P-521": return ["ES512"];
        case "secp256k1": return ["ES256K"];
        default: throw new Error(`Unsupported EC curve: ${jwk.crv}`);
      }
    case "OKP":
      return ["EdDSA"];
    case "RSA":
      return ["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"];
    default:
      throw new Error(`Unsupported key type: ${jwk.kty}`);
  }
};

// Verifies the issuer JWT signature with the supplied public JWK.
// Throws on any failure; returns jose's { payload, protectedHeader } on success.
export const verifyIssuerSignature = async (jwtString, jwk) => {
  const allowedAlgs = allowedAlgsForJwk(jwk);
  const header = base64UrlDecode(jwtString.split(".")[0]);
  if (!header?.alg || !allowedAlgs.includes(header.alg)) {
    throw new Error(`JWT header alg "${header?.alg}" is not permitted for this key (allowed: ${allowedAlgs.join(", ")})`);
  }
  const publicKey = await importJWK(jwk, header.alg);
  return jwtVerify(jwtString, publicKey, { algorithms: allowedAlgs });
};

// Verify the Key Binding JWT per the SD-JWT spec: typ must be "kb+jwt",
// sd_hash must be the _sd_alg digest over the presentation, and the
// signature must verify with the holder key from the issuer payload's cnf.jwk.
export const verifyKbJwt = async (kbJwtString, issuerPayload, presentation) => {
  const result = { ok: false, typOk: null, sdHashOk: null, sigOk: null, alg: null, error: null, sigNote: null };
  try {
    const [h, p] = kbJwtString.split(".");
    const header = base64UrlDecode(h);
    const kbPayload = base64UrlDecode(p);

    result.typOk = header?.typ === "kb+jwt";

    const sdAlg = (issuerPayload?._sd_alg || "sha-256").toLowerCase();
    if (HASH_ALGS[sdAlg]) {
      const expected = await hashB64Url(sdAlg, new TextEncoder().encode(presentation));
      result.expectedSdHash = expected;
      result.actualSdHash = kbPayload?.sd_hash ?? null;
      result.sdHashOk = kbPayload?.sd_hash === expected;
    } else {
      result.sdHashOk = false;
      result.sigNote = `Cannot check sd_hash: unsupported _sd_alg "${sdAlg}"`;
    }

    const cnfJwk = issuerPayload?.cnf?.jwk;
    if (!cnfJwk) {
      result.sigNote = "Issuer payload has no cnf.jwk — holder signature cannot be verified";
    } else {
      const allowedAlgs = allowedAlgsForJwk(cnfJwk);
      if (!header?.alg || !allowedAlgs.includes(header.alg)) {
        throw new Error(`KB-JWT header alg "${header?.alg}" is not permitted for the cnf key (allowed: ${allowedAlgs.join(", ")})`);
      }
      const holderKey = await importJWK(cnfJwk, header.alg);
      await jwtVerify(kbJwtString, holderKey, { algorithms: allowedAlgs });
      result.sigOk = true;
      result.alg = header.alg;
    }
    result.ok = result.typOk === true && result.sdHashOk === true && result.sigOk === true;
  } catch (e) {
    result.sigOk = result.sigOk === true ? true : false;
    result.error = e.message;
  }
  return result;
};
