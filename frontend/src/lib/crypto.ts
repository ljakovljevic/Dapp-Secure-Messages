export function toAB(u8: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u8.byteLength);
  new Uint8Array(ab).set(u8);
  return ab;
}
export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2) throw new Error("hex length");
  const out = new Uint8Array(h.length/2);
  for (let i=0;i<out.length;i++) out[i] = parseInt(h.slice(i*2,i*2+2),16);
  return out;
}
export function bytesToHex(b: Uint8Array): string { return "0x" + Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join(""); }
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64); const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out;
}
export function bytesToBase64(b: Uint8Array): string {
  let s=""; for (const x of b) s += String.fromCharCode(x); return btoa(s);
}

// ===== AES-GCM (256) =====
export async function aesGenKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name:"AES-GCM", length:256 }, true, ["encrypt","decrypt"]);
}
export async function aesEncrypt(plaintext: string, key: CryptoKey) {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv: toAB(iv) }, key, new TextEncoder().encode(plaintext));
  return { ciphertext: new Uint8Array(ct), iv };
}
export async function aesDecrypt(ciphertext: Uint8Array, key: CryptoKey, iv: Uint8Array) {
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv: toAB(iv) }, key, toAB(ciphertext));
  return new TextDecoder().decode(new Uint8Array(pt));
}
export async function aesExportRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}
export async function aesImportRaw(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toAB(raw), { name:"AES-GCM" }, false, ["encrypt","decrypt"]);
}

// ===== SHA-256 =====
export async function sha256Bytes(data: Uint8Array): Promise<`0x${string}`> {
  const d = await crypto.subtle.digest("SHA-256", toAB(data));
  return bytesToHex(new Uint8Array(d)) as `0x${string}`;
}
export async function sha256HexOfString(s: string): Promise<`0x${string}`> {
  return sha256Bytes(new TextEncoder().encode(s));
}

// ===== RSA-OAEP-256 =====
const subtleAny = (globalThis.crypto && (globalThis.crypto.subtle as any)) as SubtleCrypto & { importKey: any };
function sanitizeJwk(jwk: JsonWebKey, usage: "encrypt"|"decrypt") {
  const clean: any = { ...jwk, ext: true, alg: jwk.alg ?? "RSA-OAEP-256" };
  delete clean.key_ops; delete clean.use;
  return { clean, keyUsages: usage === "encrypt" ? ["encrypt"] : ["decrypt"] as KeyUsage[] };
}

export async function importRsaPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const { clean, keyUsages } = sanitizeJwk(jwk, "encrypt");
  return subtleAny.importKey("jwk", clean as JsonWebKey, { name: "RSA-OAEP", hash: "SHA-256" } as RsaHashedImportParams, true, keyUsages as KeyUsage[]);
}
export async function importRsaPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  const { clean, keyUsages } = sanitizeJwk(jwk, "decrypt");
  return subtleAny.importKey("jwk", clean as JsonWebKey, { name: "RSA-OAEP", hash: "SHA-256" } as RsaHashedImportParams, true, keyUsages as KeyUsage[]);
}
export async function rsaOaepEncrypt(pub: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const enc = await crypto.subtle.encrypt({ name:"RSA-OAEP" }, pub, toAB(data));
  return new Uint8Array(enc);
}
export async function rsaOaepDecrypt(priv: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const dec = await crypto.subtle.decrypt({ name:"RSA-OAEP" }, priv, toAB(data));
  return new Uint8Array(dec);
}