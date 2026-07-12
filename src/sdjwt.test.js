import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import {
  base64UrlDecode,
  digestDisclosureB64Url,
  sha256B64Url,
  collectAllDigests,
  verifySdListAgainstDisclosures,
  allowedAlgsForJwk,
  verifyIssuerSignature,
  verifyKbJwt,
  parseSdJwt,
  reconstructClaims,
} from "./sdjwt.js";

const b64u = (s) => Buffer.from(s).toString("base64url");
const makeDisclosure = (arr) => b64u(JSON.stringify(arr));
const fakeJwt = (header, payload) => `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}.c2ln`;

describe("base64UrlDecode", () => {
  it("decodes base64url JSON", () => {
    expect(base64UrlDecode(b64u('{"alg":"ES256"}'))).toEqual({ alg: "ES256" });
  });

  it("round-trips non-ASCII (UTF-8) claim values", () => {
    const disclosure = makeDisclosure(["salt", "givenName", "太郎"]);
    expect(base64UrlDecode(disclosure)).toEqual(["salt", "givenName", "太郎"]);
  });

  it("falls back to a plain string for non-JSON input", () => {
    expect(base64UrlDecode(b64u("hello"))).toBe("hello");
  });
});

describe("allowedAlgsForJwk", () => {
  it("maps EC curves to their single ECDSA algorithm", () => {
    expect(allowedAlgsForJwk({ kty: "EC", crv: "P-256" })).toEqual(["ES256"]);
    expect(allowedAlgsForJwk({ kty: "EC", crv: "P-384" })).toEqual(["ES384"]);
    expect(allowedAlgsForJwk({ kty: "EC", crv: "P-521" })).toEqual(["ES512"]);
  });

  it("allows only asymmetric RSA algorithms for RSA keys", () => {
    expect(allowedAlgsForJwk({ kty: "RSA" })).toEqual(["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]);
  });

  it("maps OKP to EdDSA", () => {
    expect(allowedAlgsForJwk({ kty: "OKP", crv: "Ed25519" })).toEqual(["EdDSA"]);
  });

  it("rejects symmetric (oct) keys", () => {
    expect(() => allowedAlgsForJwk({ kty: "oct", k: "c2VjcmV0" })).toThrow(/Symmetric/);
  });

  it("rejects a symmetric alg pinned on the JWK", () => {
    expect(() => allowedAlgsForJwk({ kty: "EC", crv: "P-256", alg: "HS256" })).toThrow(/not an accepted asymmetric/);
  });

  it("honors an asymmetric alg pinned on the JWK", () => {
    expect(allowedAlgsForJwk({ kty: "RSA", alg: "PS256" })).toEqual(["PS256"]);
  });

  it("rejects unknown key types and curves", () => {
    expect(() => allowedAlgsForJwk({ kty: "XYZ" })).toThrow(/Unsupported key type/);
    expect(() => allowedAlgsForJwk({ kty: "EC", crv: "brainpoolP256r1" })).toThrow(/Unsupported EC curve/);
    expect(() => allowedAlgsForJwk(null)).toThrow(/JWK object/);
  });
});

describe("collectAllDigests", () => {
  it("collects _sd arrays and \"...\" values at any depth", () => {
    const payload = {
      _sd: ["a", "b"],
      nested: { deeper: { _sd: ["c"] }, arr: [{ "...": "d" }] },
    };
    expect(collectAllDigests(payload).sort()).toEqual(["a", "b", "c", "d"]);
  });
});

describe("verifySdListAgainstDisclosures", () => {
  const disclose = async (arr) => {
    const raw = makeDisclosure(arr);
    return { raw, decoded: arr, digest: await digestDisclosureB64Url(raw) };
  };

  it("matches valid disclosures against payload anchors", async () => {
    const d = await disclose(["salt", "name", "value"]);
    const payload = { _sd: [d.digest], _sd_alg: "sha-256" };
    const res = await verifySdListAgainstDisclosures(payload, [d]);
    expect(res.ok).toBe(true);
    expect(res.matches).toHaveLength(1);
    expect(res.missing).toHaveLength(0);
    expect(res.duplicates).toHaveLength(0);
  });

  it("flags forged disclosures (not anchored in the payload) as missing", async () => {
    const good = await disclose(["salt1", "name", "value"]);
    const forged = await disclose(["salt2", "forgedClaim", "evil"]);
    const payload = { _sd: [good.digest] };
    const res = await verifySdListAgainstDisclosures(payload, [good, forged]);
    expect(res.ok).toBe(false);
    expect(res.missing.map((m) => m.disclosure)).toEqual([forged.raw]);
    expect(res.matches.map((m) => m.disclosure)).toEqual([good.raw]);
  });

  it("rejects duplicate disclosures", async () => {
    const d = await disclose(["salt", "name", "value"]);
    const payload = { _sd: [d.digest] };
    const res = await verifySdListAgainstDisclosures(payload, [d, d]);
    expect(res.ok).toBe(false);
    expect(res.duplicates).toEqual([d.digest]);
  });

  it("rejects duplicate digest anchors in the payload", async () => {
    const d = await disclose(["salt", "name", "value"]);
    const payload = { _sd: [d.digest], nested: { _sd: [d.digest] } };
    const res = await verifySdListAgainstDisclosures(payload, [d]);
    expect(res.ok).toBe(false);
    expect(res.duplicates).toEqual([d.digest]);
  });

  it("finds anchors nested inside other disclosures (recursive disclosures)", async () => {
    const inner = await disclose(["salt1", "innerClaim", "v"]);
    const outer = await disclose(["salt2", "outerClaim", { _sd: [inner.digest] }]);
    const payload = { _sd: [outer.digest] };
    const res = await verifySdListAgainstDisclosures(payload, [outer, inner]);
    expect(res.ok).toBe(true);
    expect(res.matches).toHaveLength(2);
  });

  it("reports unsupported _sd_alg", async () => {
    const d = await disclose(["salt", "name", "value"]);
    const res = await verifySdListAgainstDisclosures({ _sd: [d.digest], _sd_alg: "sha3-256" }, [d]);
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/Unsupported _sd_alg/);
  });
});

describe("reconstructClaims", () => {
  it("applies only digest-matched disclosures and strips _sd/_sd_alg", () => {
    const matched = { raw: "m", decoded: ["s1", "goodClaim", "yes"] };
    const unmatched = { raw: "u", decoded: ["s2", "forgedClaim", "no"] };
    const claims = reconstructClaims(
      { iss: "x", _sd: ["digest"], _sd_alg: "sha-256" },
      [matched, unmatched],
      new Set(["m"])
    );
    expect(claims).toEqual({ iss: "x", goodClaim: "yes" });
  });

  it("refuses prototype-polluting claim names", () => {
    const evil = { raw: "e", decoded: ["s", "__proto__", { polluted: true }] };
    const claims = reconstructClaims({ iss: "x" }, [evil], new Set(["e"]));
    expect(Object.prototype.polluted).toBeUndefined();
    expect({}.polluted).toBeUndefined();
    expect(Object.keys(claims)).toEqual(["iss"]);
  });
});

describe("parseSdJwt", () => {
  const jwt = fakeJwt({ alg: "ES256" }, { iss: "https://issuer.example" });
  const disclosure = makeDisclosure(["salt", "name", "value"]);

  it("parses jwt + disclosures with a trailing ~ (no KB-JWT)", () => {
    const res = parseSdJwt(`${jwt}~${disclosure}~`);
    expect(res.header).toEqual({ alg: "ES256" });
    expect(res.payload).toEqual({ iss: "https://issuer.example" });
    expect(res.disclosures.map((d) => d.raw)).toEqual([disclosure]);
    expect(res.kbJwt).toBeNull();
    expect(res.presentation).toBeNull();
  });

  it("treats a dotted final segment as the KB-JWT and computes the presentation", () => {
    const kb = fakeJwt({ alg: "ES256", typ: "kb+jwt" }, { sd_hash: "x" });
    const res = parseSdJwt(`${jwt}~${disclosure}~${kb}`);
    expect(res.kbJwt?.raw).toBe(kb);
    expect(res.kbJwt?.header?.typ).toBe("kb+jwt");
    expect(res.presentation).toBe(`${jwt}~${disclosure}~`);
  });

  it("does not treat a dotted middle segment as a KB-JWT", () => {
    const res = parseSdJwt(`${jwt}~a.b.c~${disclosure}~`);
    expect(res.kbJwt).toBeNull();
    expect(res.disclosures.map((d) => d.raw)).toContain(disclosure);
  });

  it("strips whitespace and newlines before parsing", () => {
    const res = parseSdJwt(`${jwt.slice(0, 10)}\n ${jwt.slice(10)}~\n${disclosure}~`);
    expect(res.payload).toEqual({ iss: "https://issuer.example" });
    expect(res.disclosures).toHaveLength(1);
  });

  it("throws on a malformed JWT", () => {
    expect(() => parseSdJwt("not-a-jwt~")).toThrow(/Invalid JWT format/);
  });
});

describe("verifyIssuerSignature", () => {
  let issuer, issuerJwk, otherJwk, signedJwt;

  beforeAll(async () => {
    issuer = await generateKeyPair("ES256", { extractable: true });
    const other = await generateKeyPair("ES256", { extractable: true });
    issuerJwk = await exportJWK(issuer.publicKey);
    otherJwk = await exportJWK(other.publicKey);
    signedJwt = await new SignJWT({ iss: "https://issuer.example" })
      .setProtectedHeader({ alg: "ES256", typ: "dc+sd-jwt" })
      .sign(issuer.privateKey);
  });

  it("verifies a valid signature", async () => {
    const { protectedHeader } = await verifyIssuerSignature(signedJwt, issuerJwk);
    expect(protectedHeader.alg).toBe("ES256");
  });

  it("rejects a wrong key", async () => {
    await expect(verifyIssuerSignature(signedJwt, otherJwk)).rejects.toThrow(/signature verification failed/);
  });

  it("rejects a header alg outside the key-derived allowlist (algorithm confusion)", async () => {
    const [, payload, sig] = signedJwt.split(".");
    const confused = `${b64u(JSON.stringify({ alg: "HS256" }))}.${payload}.${sig}`;
    await expect(verifyIssuerSignature(confused, issuerJwk)).rejects.toThrow(/not permitted for this key/);
  });

  it("rejects an unsecured (alg none) JWT", async () => {
    const [, payload] = signedJwt.split(".");
    const unsecured = `${b64u(JSON.stringify({ alg: "none" }))}.${payload}.`;
    await expect(verifyIssuerSignature(unsecured, issuerJwk)).rejects.toThrow(/not permitted for this key/);
  });

  it("rejects symmetric JWKs outright", async () => {
    await expect(verifyIssuerSignature(signedJwt, { kty: "oct", k: "c2VjcmV0" })).rejects.toThrow(/Symmetric/);
  });
});

describe("verifyKbJwt", () => {
  let holder, holderJwk, issuerPayload, presentation, kbJwt;

  const signKb = async (key, { typ = "kb+jwt", sdHash }) =>
    new SignJWT({ nonce: "n-123", aud: "https://verifier.example", iat: Math.floor(Date.now() / 1000), sd_hash: sdHash })
      .setProtectedHeader({ alg: "ES256", typ })
      .sign(key);

  beforeAll(async () => {
    holder = await generateKeyPair("ES256", { extractable: true });
    holderJwk = await exportJWK(holder.publicKey);
    issuerPayload = { iss: "https://issuer.example", _sd_alg: "sha-256", cnf: { jwk: holderJwk } };
    presentation = "issuer-jwt~disclosure~";
    const sdHash = await sha256B64Url(new TextEncoder().encode(presentation));
    kbJwt = await signKb(holder.privateKey, { sdHash });
  });

  it("verifies a valid KB-JWT (typ, sd_hash, holder signature)", async () => {
    const res = await verifyKbJwt(kbJwt, issuerPayload, presentation);
    expect(res).toMatchObject({ ok: true, typOk: true, sdHashOk: true, sigOk: true, alg: "ES256" });
  });

  it("fails when the presentation does not match sd_hash (replay over altered SD-JWT)", async () => {
    const res = await verifyKbJwt(kbJwt, issuerPayload, presentation + "extra~");
    expect(res.ok).toBe(false);
    expect(res.sdHashOk).toBe(false);
    expect(res.sigOk).toBe(true); // signature itself is intact
  });

  it("fails on a wrong typ header", async () => {
    const sdHash = await sha256B64Url(new TextEncoder().encode(presentation));
    const wrongTyp = await signKb(holder.privateKey, { typ: "JWT", sdHash });
    const res = await verifyKbJwt(wrongTyp, issuerPayload, presentation);
    expect(res.ok).toBe(false);
    expect(res.typOk).toBe(false);
  });

  it("fails when signed by a key other than cnf.jwk", async () => {
    const impostor = await generateKeyPair("ES256", { extractable: true });
    const sdHash = await sha256B64Url(new TextEncoder().encode(presentation));
    const forged = await signKb(impostor.privateKey, { sdHash });
    const res = await verifyKbJwt(forged, issuerPayload, presentation);
    expect(res.ok).toBe(false);
    expect(res.sigOk).toBe(false);
    expect(res.error).toMatch(/signature verification failed/);
  });

  it("reports a missing cnf.jwk", async () => {
    const res = await verifyKbJwt(kbJwt, { iss: "x" }, presentation);
    expect(res.ok).toBe(false);
    expect(res.sigOk).toBe(null);
    expect(res.sigNote).toMatch(/no cnf\.jwk/);
  });
});
