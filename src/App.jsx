import React, { useEffect, useMemo, useState } from "react";
import { importJWK, jwtVerify } from "jose";

// Note: This file is a Vite/React port of the previously single-file (Babel-in-browser) implementation.
// Tailwind classes are preserved to keep the original appearance.

const DANGEROUS_KEYS = new Set(["__proto__", "prototype", "constructor"]);
function safeSetClaim(obj, key, value) {
  if (typeof key !== "string") return;
  if (DANGEROUS_KEYS.has(key)) return;
  obj[key] = value;
}

// Lucide React icons as simple SVG components
        const AlertCircle = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
        );

        const CheckCircle = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
        );

        const Copy = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        );

        const Info = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
        );

        const XCircle = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
        );

        const Shield = ({ className, size = 24 }) => (
            <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            </svg>
        );

        const SDJWTDecoder = () => {
            const [input, setInput] = useState('');
            const [publicKeyInput, setPublicKeyInput] = useState('');
            const [decoded, setDecoded] = useState(null);
            const [error, setError] = useState('');
            const [copied, setCopied] = useState(false);
            const [verificationStatus, setVerificationStatus] = useState(null);
            const [verifying, setVerifying] = useState(false);

            const base64UrlDecode = (str) => {
                // Decode via bytes + TextDecoder so non-ASCII (UTF-8) claim values survive
                const text = new TextDecoder("utf-8").decode(base64UrlToBytes(str));
                try {
                    return JSON.parse(text);
                } catch (e) {
                    return text;
                }
            };
            // --- SD-JWT _sd digest verification helpers (sha-256) ---
            const base64UrlToBytes = (b64url) => {
                const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
                const b64 = (b64url.replace(/-/g, "+").replace(/_/g, "/") + pad);
                const str = atob(b64);
                const bytes = new Uint8Array(str.length);
                for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
                return bytes;
            };
            const bytesToBase64Url = (bytes) => {
                let bin = "";
                bytes.forEach(b => bin += String.fromCharCode(b));
                return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
            };
            const sha256B64Url = async (bytes) => {
                if (!crypto?.subtle) throw new Error("Web Crypto SubtleCrypto unavailable (use HTTPS or localhost).");
                const digest = await crypto.subtle.digest("SHA-256", bytes);
                return bytesToBase64Url(new Uint8Array(digest));
            };
            const digestDisclosureB64Url = async (disclosureB64Url) => {
                // Digest over UTF-8 of the BASE64URL disclosure string per SD-JWT spec
                const bytes = new TextEncoder().encode(disclosureB64Url);
                return sha256B64Url(bytes);
            };
            // Recursively collect digest anchors from payload:
            //  - any array under key "_sd"
            //  - any object's "..." value
            const collectAllDigests = (node, acc = []) => {
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
            const verifySdListAgainstDisclosures = async (payload, disclosures) => {
                const sdAlg = (payload?._sd_alg || "sha-256").toLowerCase();
                // Digest anchors live in the payload AND inside disclosure values
                // (recursive disclosures per the SD-JWT spec), so collect from both.
                const anchorList = collectAllDigests(payload);
                for (const d of disclosures) collectAllDigests(d.decoded, anchorList);
                const allDigests = new Set(anchorList);
                if (sdAlg !== "sha-256") {
                    return { ok: false, alg: sdAlg, reason: "Unsupported _sd_alg", matches: [], missing: [], extra: Array.from(allDigests), duplicates: [] };
                }
                const computed = await Promise.all(
                    disclosures.map(async (d) => ({ disclosure: d.raw, digest: await digestDisclosureB64Url(d.raw) }))
                );
                const matches = [];
                const missing = [];
                for (const c of computed) {
                    if (allDigests.has(c.digest)) matches.push(c);
                    else missing.push(c);
                }
                const computedDigests = new Set(computed.map(c => c.digest));
                const extra = Array.from(allDigests).filter(d => !computedDigests.has(d));
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


            // Allowed signature algorithms are derived from the *key*, never from the
            // attacker-controlled JWT header, to prevent algorithm-confusion attacks.
            const ASYMMETRIC_ALGS = new Set([
                "ES256", "ES384", "ES512", "ES256K",
                "RS256", "RS384", "RS512",
                "PS256", "PS384", "PS512",
                "EdDSA", "Ed25519", "Ed448"
            ]);
            const allowedAlgsForJwk = (jwk) => {
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

            const verifySignature = async (jwtString, publicKeyJwk) => {
                try {
                    setVerifying(true);
                    setVerificationStatus(null);

                    // Parse the public key (remove any newlines first)
                    let jwk;
                    if (typeof publicKeyJwk === 'string') {
                        const cleanedKey = publicKeyJwk.replace(/[\r\n]/g, '');
                        jwk = JSON.parse(cleanedKey);
                    } else {
                        jwk = publicKeyJwk;
                    }

                    const allowedAlgs = allowedAlgsForJwk(jwk);
                    const header = base64UrlDecode(jwtString.split('.')[0]);
                    if (!header?.alg || !allowedAlgs.includes(header.alg)) {
                        throw new Error(`JWT header alg "${header?.alg}" is not permitted for this key (allowed: ${allowedAlgs.join(', ')})`);
                    }

                    // Import the public key
                    const publicKey = await importJWK(jwk, header.alg);

                    // Verify the JWT against the key-derived algorithm allowlist
                    const { payload, protectedHeader } = await jwtVerify(jwtString, publicKey, {
                        algorithms: allowedAlgs
                    });

                    setVerificationStatus({
                        success: true,
                        message: 'Verification succeeded',
                        algorithm: protectedHeader.alg
                    });

                } catch (err) {
                    console.error('Verification error:', err);
                    setVerificationStatus({
                        success: false,
                        message: 'Verification failed',
                        error: err.message
                    });
                } finally {
                    setVerifying(false);
                }
            };

            // Verify the Key Binding JWT per the SD-JWT spec: typ must be "kb+jwt",
            // sd_hash must be the _sd_alg digest over the presentation (issuer JWT +
            // disclosures + trailing "~"), and the signature must verify with the
            // holder key from the issuer payload's cnf.jwk.
            const verifyKbJwt = async (kbJwtString, issuerPayload, presentation) => {
                const result = { ok: false, typOk: null, sdHashOk: null, sigOk: null, alg: null, error: null, sigNote: null };
                try {
                    const [h, p] = kbJwtString.split('.');
                    const header = base64UrlDecode(h);
                    const kbPayload = base64UrlDecode(p);

                    result.typOk = header?.typ === 'kb+jwt';

                    const sdAlg = (issuerPayload?._sd_alg || 'sha-256').toLowerCase();
                    if (sdAlg === 'sha-256') {
                        const expected = await sha256B64Url(new TextEncoder().encode(presentation));
                        result.expectedSdHash = expected;
                        result.actualSdHash = kbPayload?.sd_hash ?? null;
                        result.sdHashOk = kbPayload?.sd_hash === expected;
                    } else {
                        result.sdHashOk = false;
                        result.sigNote = `Cannot check sd_hash: unsupported _sd_alg "${sdAlg}"`;
                    }

                    const cnfJwk = issuerPayload?.cnf?.jwk;
                    if (!cnfJwk) {
                        result.sigNote = 'Issuer payload has no cnf.jwk — holder signature cannot be verified';
                    } else {
                        const allowedAlgs = allowedAlgsForJwk(cnfJwk);
                        if (!header?.alg || !allowedAlgs.includes(header.alg)) {
                            throw new Error(`KB-JWT header alg "${header?.alg}" is not permitted for the cnf key (allowed: ${allowedAlgs.join(', ')})`);
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

            const decodeSDJWT = async (sdJwt) => {
                try {
                    setError('');
                    setVerificationStatus(null);
                    
                    // Remove all newlines and whitespace to handle multi-line input from spec documents
                    const cleanedSdJwt = sdJwt.replace(/[\r\n\s]/g, '');
                    
                    const parts = cleanedSdJwt.trim().split('~');
                    const jwtString = parts[0];
                    const jwtParts = jwtString.split('.');
                    if (jwtParts.length !== 3) {
                        throw new Error('Invalid JWT format');
                    }

                    const header = base64UrlDecode(jwtParts[0]);
                    const payload = base64UrlDecode(jwtParts[1]);
                    const signature = jwtParts[2];

                    const disclosures = [];
                    let kbJwt = null;

                    for (let i = 1; i < parts.length; i++) {
                        const part = parts[i].trim();
                        if (!part) continue;

                        // Per the SD-JWT spec, a Key Binding JWT can only be the last
                        // element (disclosures are dot-free base64url, so a dotted
                        // segment anywhere else is malformed rather than a KB-JWT).
                        if (i === parts.length - 1 && part.split('.').length === 3) {
                            const kbParts = part.split('.');
                            kbJwt = {
                                raw: part,
                                header: base64UrlDecode(kbParts[0]),
                                payload: base64UrlDecode(kbParts[1]),
                                signature: kbParts[2]
                            };
                        } else {
                            try {
                                const disclosure = base64UrlDecode(part);
                                disclosures.push({
                                    raw: part,
                                    decoded: disclosure
                                });
                            } catch (e) {
                                console.warn('Failed to decode disclosure:', part);
                            }
                        }
                    }

                    // Verify _sd digest list against disclosures (including nested anchors)
                    // BEFORE reconstructing claims, so forged disclosures appended to a
                    // signed SD-JWT are never merged into the reconstructed claim set.
                    let sdVerification = null;
                    let matchedDisclosures = new Set();
                    try {
                        sdVerification = await verifySdListAgainstDisclosures(payload, disclosures);
                        matchedDisclosures = new Set((sdVerification.matches || []).map(m => m.disclosure));
                    } catch (e) {
                        sdVerification = { ok: false, error: e.message };
                    }

                    const reconstructedClaims = JSON.parse(JSON.stringify(payload));

                    disclosures.forEach(disc => {
                        if (!matchedDisclosures.has(disc.raw)) return; // digest-verified only
                        if (Array.isArray(disc.decoded) && disc.decoded.length >= 2) {
                            const [salt, claimName, claimValue] = disc.decoded;
                            if (claimName && claimValue !== undefined) {
                                safeSetClaim(reconstructedClaims, claimName, claimValue);
                            }
                        }
                    });

                    const cleanedClaims = { ...reconstructedClaims };
                    delete cleanedClaims._sd;
                    delete cleanedClaims._sd_alg;

                    // Verify the KB-JWT (if present) against cnf.jwk and sd_hash.
                    // The presentation the sd_hash covers is everything up to and
                    // including the last "~" before the KB-JWT.
                    let kbVerification = null;
                    if (kbJwt) {
                        const presentation = parts.slice(0, -1).join('~') + '~';
                        kbVerification = await verifyKbJwt(kbJwt.raw, payload, presentation);
                    }
setDecoded({
                        jwt: {
                            header,
                            payload,
                            signature
                        },
                        jwtString,
                        disclosures,
                        kbJwt,
                        kbVerification,
                        reconstructedClaims: cleanedClaims,
                        originalPayload: payload,
                        sdVerification
                    });

                    // Perform verification if public key is provided
                    if (publicKeyInput.trim()) {
                        await verifySignature(jwtString, publicKeyInput);
                    }

                } catch (err) {
                    setError(err.message);
                    setDecoded(null);
                }
            };

            const handleDecode = () => {
                if (!input.trim()) {
                    setError('Please enter an SD-JWT');
                    return;
                }
                decodeSDJWT(input);
            };

            const handleVerify = async () => {
                if (!decoded) {
                    setError('Please decode an SD-JWT first');
                    return;
                }
                if (!publicKeyInput.trim()) {
                    setError('Please provide a public key');
                    return;
                }
                await verifySignature(decoded.jwtString, publicKeyInput);
            };

            const copyToClipboard = (text) => {
                navigator.clipboard.writeText(JSON.stringify(text, null, 2));
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
            };

            // Store example with newlines as in the spec, will be cleaned when loaded
            const exampleSDJWT = `eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIzLTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDExOjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRlIiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhiWlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVllZy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3laUmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVOdzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRCeTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1XZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxkTURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0MtX29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJfc2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEiLCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQbjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAiVmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0.OZomvwO8iw4db89MYCeeomBVStXkT6u7G7FkicPWZnd2_hGgr0l_u1NHgPVocuOt-m32Uu6kwtPmYFxKk0AOeA~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiwgIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgIm1hcmtldGluZ0F1dGhvcml6YXRpb25Ib2xkZXIiLCAiTW9kZXJuYSBCaW90ZWNoIl0~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm5leHRWYWNjaW5hdGlvbkRhdGUiLCAiMjAyMS0wOC0xNlQxMzo0MDoxMloiXQ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImNvdW50cnlPZlZhY2NpbmF0aW9uIiwgIkdFIl0~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjIwMjEtMDYtMjNUMTM6NDA6MTJaIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdlbmRlciIsICJGZW1hbGUiXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImJpcnRoRGF0ZSIsICIxOTYxLTA4LTE3Il0~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgImdpdmVuTmFtZSIsICJNYXJpb24iXQ~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImZhbWlseU5hbWUiLCAiTXVzdGVybWFubiJd~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImFkbWluaXN0ZXJpbmdDZW50cmUiLCAiUHJheGlzIFNvbW1lcmdhcnRlbiJd~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImJhdGNoTnVtYmVyIiwgIjE2MjYzODI3MzYiXQ~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImhlYWx0aFByb2Zlc3Npb25hbCIsICI4ODMxMTAwMDAwMTUzNzYiXQ~`;

            const examplePublicKey = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
  "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
}`;

            return (
                <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
                    <div className="max-w-6xl mx-auto">
                        <div className="bg-white rounded-lg shadow-xl p-8 mb-6">
                            <div className="flex items-center gap-3 mb-6">
                                <div className="bg-indigo-600 p-3 rounded-lg">
                                    <Info className="text-white" size={28} />
                                </div>
                                <div>
                                    <h1 className="text-3xl font-bold text-gray-800">SD-JWT Decoder with Verification</h1>
                                    <p className="text-gray-600">Decode and verify Selective Disclosure JSON Web Tokens</p>
                                </div>
                            </div>

                            <div className="mb-4">
                                <div className="flex justify-between items-center mb-2">
                                    <label className="block text-sm font-medium text-gray-700">
                                        SD-JWT Input
                                    </label>
                                    <button
                                        onClick={() => {
                                            setInput(exampleSDJWT);
                                            setPublicKeyInput(examplePublicKey);
                                        }}
                                        className="text-sm text-indigo-600 hover:text-indigo-800"
                                    >
                                        Load Example
                                    </button>
                                </div>
                                <textarea
                                    value={input}
                                    onChange={(e) => setInput(e.target.value)}
                                    placeholder="Paste your SD-JWT here (format: jwt~disclosure1~disclosure2~...)"
                                    className="w-full h-32 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-sm"
                                />
                            </div>

                            <div className="mb-4">
                                <div className="flex justify-between items-center mb-2">
                                    <label className="block text-sm font-medium text-gray-700">
                                        Issuer Public Key (JWK format - optional)
                                    </label>
                                    <button
                                        onClick={() => setPublicKeyInput(examplePublicKey)}
                                        className="text-sm text-indigo-600 hover:text-indigo-800"
                                    >
                                        Load Example Key
                                    </button>
                                </div>
                                <textarea
                                    value={publicKeyInput}
                                    onChange={(e) => setPublicKeyInput(e.target.value)}
                                    placeholder='{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}'
                                    className="w-full h-24 p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent font-mono text-sm"
                                />
                                <p className="text-xs text-gray-500 mt-1">
                                    Example from IETF OAuth SD-JWT Draft Specification
                                </p>
                            </div>

                            <button
                                onClick={handleDecode}
                                className="w-full bg-indigo-600 text-white py-3 rounded-lg font-semibold hover:bg-indigo-700 transition-colors mb-2"
                            >
                                Decode SD-JWT
                            </button>

                            {decoded && publicKeyInput.trim() && (
                                <button
                                    onClick={handleVerify}
                                    disabled={verifying}
                                    className="w-full bg-green-600 text-white py-3 rounded-lg font-semibold hover:bg-green-700 transition-colors disabled:bg-gray-400"
                                >
                                    {verifying ? 'Verifying...' : 'Verify Signature'}
                                </button>
                            )}

                            {error && (
                                <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-2">
                                    <AlertCircle className="text-red-500 flex-shrink-0 mt-0.5" size={20} />
                                    <div>
                                        <p className="font-semibold text-red-800">Error</p>
                                        <p className="text-red-600 text-sm">{error}</p>
                                    </div>
                                </div>
                            )}

                            {decoded && !publicKeyInput.trim() && (
                                <div className="mt-4 p-4 bg-yellow-50 border border-yellow-200 rounded-lg flex items-start gap-2">
                                    <AlertCircle className="text-yellow-600 flex-shrink-0 mt-0.5" size={20} />
                                    <div>
                                        <p className="font-semibold text-yellow-800">Verification Info</p>
                                        <p className="text-yellow-700 text-sm">To perform verification, please provide the issuer's public key</p>
                                    </div>
                                </div>
                            )}

                            {verificationStatus && (
                                <div className={`mt-4 p-4 rounded-lg border-2 flex items-start gap-2 ${
                                    verificationStatus.success 
                                        ? 'bg-green-50 border-green-300' 
                                        : 'bg-red-50 border-red-300'
                                }`}>
                                    {verificationStatus.success ? (
                                        <CheckCircle className="text-green-600 flex-shrink-0 mt-0.5" size={24} />
                                    ) : (
                                        <XCircle className="text-red-600 flex-shrink-0 mt-0.5" size={24} />
                                    )}
                                    <div className="flex-1">
                                        <p className={`font-bold text-lg ${
                                            verificationStatus.success ? 'text-green-800' : 'text-red-800'
                                        }`}>
                                            {verificationStatus.message}
                                        </p>
                                        {verificationStatus.success && (
                                            <p className="text-green-700 text-sm mt-1">
                                                Algorithm: {verificationStatus.algorithm}
                                            </p>
                                        )}
                                        {!verificationStatus.success && verificationStatus.error && (
                                            <p className="text-red-600 text-sm mt-1">
                                                {verificationStatus.error}
                                            </p>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>

                        {decoded && (
                            <div className="space-y-6">
                                <div className="bg-white rounded-lg shadow-lg p-6">
                                    <div className="flex items-center justify-between mb-4">
                                        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                                            <Shield className="text-indigo-600" size={24} />
                                            JWT Header
                                        </h2>
                                        <button
                                            onClick={() => copyToClipboard(decoded.jwt.header)}
                                            className="text-indigo-600 hover:text-indigo-800 flex items-center gap-1"
                                        >
                                            <Copy size={18} />
                                            {copied ? 'Copied!' : 'Copy'}
                                        </button>
                                    </div>
                                    <pre className="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">
                                        {JSON.stringify(decoded.jwt.header, null, 2)}
                                    </pre>
                                </div>

                                <div className="bg-white rounded-lg shadow-lg p-6">
                                    <div className="flex items-center justify-between mb-4">
                                        <h2 className="text-xl font-bold text-gray-800">JWT Payload (Original)</h2>
                                        <button
                                            onClick={() => copyToClipboard(decoded.originalPayload)}
                                            className="text-indigo-600 hover:text-indigo-800 flex items-center gap-1"
                                        >
                                            <Copy size={18} />
                                            {copied ? 'Copied!' : 'Copy'}
                                        </button>
                                    </div>
                                    <pre className="bg-gray-50 p-4 rounded-lg overflow-x-auto text-sm">
                                        {JSON.stringify(decoded.originalPayload, null, 2)}
                                    </pre>
                                </div>

                                {decoded.disclosures.length > 0 && (
                                    <div className="bg-white rounded-lg shadow-lg p-6">
                                        <h2 className="text-xl font-bold text-gray-800 mb-4">
                                            Disclosures ({decoded.disclosures.length})
                                        </h2>
                                        <div className="space-y-4">
                                            {decoded.disclosures.map((disc, idx) => (
                                                <div key={idx} className="border border-gray-200 rounded-lg p-4">
                                                    <div className="flex justify-between items-start mb-2">
                                                        <h3 className="font-semibold text-gray-700">Disclosure {idx + 1}</h3>
                                                        <button
                                                            onClick={() => copyToClipboard(disc.decoded)}
                                                            className="text-indigo-600 hover:text-indigo-800 text-sm flex items-center gap-1"
                                                        >
                                                            <Copy size={16} />
                                                        </button>
                                                    </div>
                                                    <div className="mb-2">
                                                        <p className="text-xs text-gray-500 mb-1">Base64URL:</p>
                                                        <p className="text-xs font-mono bg-gray-50 p-2 rounded break-all">
                                                            {disc.raw}
                                                        </p>
                                                    </div>
                                                    <div>
                                                        <p className="text-xs text-gray-500 mb-1">Decoded:</p>
                                                        <pre className="text-sm bg-indigo-50 p-3 rounded overflow-x-auto">
                                                            {JSON.stringify(disc.decoded, null, 2)}
                                                        </pre>
                                                    </div>
                                                    {Array.isArray(disc.decoded) && disc.decoded.length >= 3 && (
                                                        <div className="mt-2 text-sm text-gray-600">
                                                            <span className="font-semibold">Claim:</span> {disc.decoded[1]} ={' '}
                                                            {JSON.stringify(disc.decoded[2])}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                <div className="bg-gradient-to-r from-green-50 to-emerald-50 rounded-lg shadow-lg p-6 border-2 border-green-200">
                                    
                                {/* SD Digest Verification */}
                                <div className="bg-white rounded-lg shadow-lg p-6">
                                    <div className="flex items-center gap-2 mb-3">
                                        <Shield className={decoded?.sdVerification?.ok ? "text-green-600" : "text-red-600"} size={22} />
                                        <h2 className="text-lg font-semibold text-gray-800">SD Digest Verification</h2>
                                    </div>
                                    {!decoded?.sdVerification && (
                                        <p className="text-sm text-gray-600">No verification run yet.</p>
                                    )}
                                    {decoded?.sdVerification && (
                                        <>
                                            {decoded.sdVerification.error ? (
                                                <p className="text-sm text-red-600">Error: {decoded.sdVerification.error}</p>
                                            ) : (
                                                <>
                                                    <p className="text-sm">
                                                        <span className="font-medium">Algorithm:</span> {decoded.sdVerification.alg || "sha-256"}
                                                    </p>
                                                    <p className={decoded.sdVerification.ok ? "mt-1 text-sm text-green-700" : "mt-1 text-sm text-red-700"}>
                                                        {decoded.sdVerification.ok
                                                            ? "All provided disclosures are present in the payload’s _sd list (including nested anchors), with no duplicate digests."
                                                            : decoded.sdVerification.missing?.length
                                                                ? "Some provided disclosures are NOT present in the payload’s _sd list (including nested anchors)."
                                                                : "Duplicate digests detected — the SD-JWT spec requires rejecting this token."}
                                                    </p>
                                                    {decoded.sdVerification.duplicates?.length > 0 && decoded.sdVerification.missing?.length > 0 && (
                                                        <p className="mt-1 text-sm text-red-700">
                                                            Duplicate digests were also detected — the SD-JWT spec requires rejecting this token.
                                                        </p>
                                                    )}
                                                    <div className="grid md:grid-cols-3 gap-4 mt-4 text-sm">
                                                        <div className="border rounded p-3">
                                                            <div className="font-medium mb-1">Summary</div>
                                                            <ul className="list-disc list-inside text-gray-700">
                                                                <li>Digest anchors in payload: {decoded.sdVerification.totalSd ?? "—"}</li>
                                                                <li>Disclosures provided: {decoded.sdVerification.disclosed ?? "—"}</li>
                                                                <li>Matched: {decoded.sdVerification.matches?.length ?? 0}</li>
                                                                <li>Missing: {decoded.sdVerification.missing?.length ?? 0}</li>
                                                                <li>Extra (in payload but undisclosed): {decoded.sdVerification.extra?.length ?? 0}</li>
                                                                <li className={decoded.sdVerification.duplicates?.length ? "text-red-700 font-medium" : undefined}>
                                                                    Duplicate digests: {decoded.sdVerification.duplicates?.length ?? 0}
                                                                </li>
                                                            </ul>
                                                        </div>
                                                        <div className="border rounded p-3">
                                                            <div className="font-medium mb-1">Missing (not found in payload)</div>
                                                            <ol className="space-y-1 text-gray-700">
                                                                {decoded.sdVerification.missing?.length
                                                                    ? decoded.sdVerification.missing.map((m, i) => (
                                                                        <li key={i} className="break-all font-mono">{m.digest}</li>
                                                                    ))
                                                                    : <li className="text-gray-500">None</li>}
                                                            </ol>
                                                        </div>
                                                        <div className="border rounded p-3">
                                                            <div className="font-medium mb-1">Extra (anchors in payload)</div>
                                                            <ol className="space-y-1 text-gray-700">
                                                                {decoded.sdVerification.extra?.length
                                                                    ? decoded.sdVerification.extra.map((d, i) => (
                                                                        <li key={i} className="break-all font-mono">{d}</li>
                                                                    ))
                                                                    : <li className="text-gray-500">None</li>}
                                                            </ol>
                                                        </div>
                                                    </div>
                                                    {decoded.sdVerification.duplicates?.length > 0 && (
                                                        <div className="border border-red-300 rounded p-3 mt-4 text-sm">
                                                            <div className="font-medium mb-1 text-red-800">Duplicate digests</div>
                                                            <ol className="space-y-1 text-red-700">
                                                                {decoded.sdVerification.duplicates.map((d, i) => (
                                                                    <li key={i} className="break-all font-mono">{d}</li>
                                                                ))}
                                                            </ol>
                                                        </div>
                                                    )}
                                                </>
                                            )}
                                        </>
                                    )}
                                </div>
<div className="flex items-center justify-between mb-4">
                                        <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                                            <CheckCircle className="text-green-600" size={24} />
                                            Reconstructed Claims
                                        </h2>
                                        <button
                                            onClick={() => copyToClipboard(decoded.reconstructedClaims)}
                                            className="text-green-600 hover:text-green-800 flex items-center gap-1"
                                        >
                                            <Copy size={18} />
                                            {copied ? 'Copied!' : 'Copy'}
                                        </button>
                                    </div>
                                    <p className="text-sm text-gray-600 mb-3">
                                        Claims with all digest-verified disclosures applied (disclosures that fail the _sd digest check are excluded — see SD Digest Verification above)
                                    </p>
                                    <pre className="bg-white p-4 rounded-lg overflow-x-auto text-sm border border-green-200">
                                        {JSON.stringify(decoded.reconstructedClaims, null, 2)}
                                    </pre>
                                </div>

                                {decoded.kbJwt && (
                                    <div className="bg-white rounded-lg shadow-lg p-6">
                                        <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                                            <Shield className={decoded.kbVerification?.ok ? "text-green-600" : "text-red-600"} size={22} />
                                            Key Binding JWT (KB-JWT)
                                        </h2>
                                        {decoded.kbVerification && (
                                            <div className={`mb-4 p-4 rounded-lg border-2 text-sm ${
                                                decoded.kbVerification.ok ? "bg-green-50 border-green-300" : "bg-red-50 border-red-300"
                                            }`}>
                                                <p className={`font-bold ${decoded.kbVerification.ok ? "text-green-800" : "text-red-800"}`}>
                                                    {decoded.kbVerification.ok ? "KB-JWT verification succeeded" : "KB-JWT verification failed"}
                                                </p>
                                                <ul className="mt-2 space-y-1 text-gray-800">
                                                    <li>
                                                        {decoded.kbVerification.typOk ? "✓" : "✗"} Header typ is "kb+jwt"
                                                    </li>
                                                    <li>
                                                        {decoded.kbVerification.sdHashOk ? "✓" : "✗"} sd_hash matches the presented SD-JWT
                                                        {decoded.kbVerification.sdHashOk === false && decoded.kbVerification.expectedSdHash && (
                                                            <span className="block font-mono text-xs break-all text-red-700">
                                                                expected {decoded.kbVerification.expectedSdHash}, got {String(decoded.kbVerification.actualSdHash)}
                                                            </span>
                                                        )}
                                                    </li>
                                                    <li>
                                                        {decoded.kbVerification.sigOk ? "✓" : "✗"} Signature verifies with the holder key (cnf.jwk)
                                                        {decoded.kbVerification.alg && <span> — algorithm {decoded.kbVerification.alg}</span>}
                                                    </li>
                                                </ul>
                                                {decoded.kbVerification.sigNote && (
                                                    <p className="mt-2 text-yellow-800">{decoded.kbVerification.sigNote}</p>
                                                )}
                                                {decoded.kbVerification.error && (
                                                    <p className="mt-2 text-red-700">{decoded.kbVerification.error}</p>
                                                )}
                                                <p className="mt-2 text-xs text-gray-600">
                                                    Note: cnf.jwk is taken from the issuer JWT payload — it is only trustworthy if the issuer signature verification above succeeded.
                                                </p>
                                            </div>
                                        )}
                                        <div className="space-y-3">
                                            <div>
                                                <h3 className="font-semibold text-gray-700 mb-2">Header</h3>
                                                <pre className="bg-gray-50 p-3 rounded-lg overflow-x-auto text-sm">
                                                    {JSON.stringify(decoded.kbJwt.header, null, 2)}
                                                </pre>
                                            </div>
                                            <div>
                                                <h3 className="font-semibold text-gray-700 mb-2">Payload</h3>
                                                <pre className="bg-gray-50 p-3 rounded-lg overflow-x-auto text-sm">
                                                    {JSON.stringify(decoded.kbJwt.payload, null, 2)}
                                                </pre>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                <div className="bg-white rounded-lg shadow-lg p-6">
                                    <h2 className="text-xl font-bold text-gray-800 mb-4">JWT Signature</h2>
                                    <p className="font-mono text-sm bg-gray-50 p-4 rounded-lg break-all">
                                        {decoded.jwt.signature}
                                    </p>
                                </div>
                            </div>
                        )}

                        <div className="mt-8 bg-blue-50 rounded-lg p-6 border border-blue-200">
                            <h3 className="font-semibold text-blue-900 mb-2">About SD-JWT</h3>
                            <p className="text-sm text-blue-800 mb-3">
                                Selective Disclosure JWT (SD-JWT) is a specification that extends JSON Web Tokens to enable 
                                selective disclosure of claims. The format consists of a JWT followed by base64url-encoded 
                                disclosures separated by tildes (~). Each disclosure reveals specific claims that were hashed 
                                in the original JWT payload.
                            </p>
                            <h3 className="font-semibold text-blue-900 mb-2 mt-4">Signature Verification</h3>
                            <p className="text-sm text-blue-800 mb-3">
                                To verify the authenticity of an SD-JWT, provide the issuer's public key in JWK format. 
                                The verification process checks if the signature was created using the corresponding private key, 
                                ensuring the token hasn't been tampered with.
                            </p>
                            <h3 className="font-semibold text-blue-900 mb-2 mt-4">Example Data</h3>
                            <p className="text-sm text-blue-800">
                                The example SD-JWT and public key are from the{' '}
                                <a 
                                    href="https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-22.html" 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="underline hover:text-blue-900"
                                >
                                    IETF OAuth Selective Disclosure JWT Draft Specification
                                </a>
                                . The decoder automatically removes newlines from input, making it easy to copy examples directly from the specification.
                            </p>
                        </div>
                    </div>
                </div>
            );
        };

export default SDJWTDecoder;
