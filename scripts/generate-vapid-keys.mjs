import { webcrypto } from "node:crypto";

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const publicKey = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
const privateKey = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
if (!privateKey.d) throw new Error("VAPID private key export failed");

process.stdout.write(`VAPID_PUBLIC_KEY=${base64Url(publicKey)}\nVAPID_PRIVATE_KEY=${privateKey.d}\nVAPID_SUBJECT=mailto:security@example.com\n`);
