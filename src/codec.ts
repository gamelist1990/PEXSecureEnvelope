const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (value: string) => encoder.encode(value);
export const text = (value: ArrayBuffer | Uint8Array) =>
  decoder.decode(value instanceof Uint8Array ? value : new Uint8Array(value));

export function randomBytes(length: number) {
  if (!Number.isSafeInteger(length) || length < 1 || length > 1_048_576)
    throw new Error("Invalid random byte length");
  return crypto.getRandomValues(new Uint8Array(length));
}

export function concat(...values: Uint8Array[]) {
  const result = new Uint8Array(values.reduce((n, value) => n + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

export function base64url(value: ArrayBuffer | Uint8Array) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000)
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(value: string, maximum = 2_097_152) {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length > Math.ceil(maximum * 4 / 3) + 4)
    throw new Error("Invalid encoded value");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  if (binary.length > maximum) throw new Error("Encoded value is too large");
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

export async function importAesKey(secret: string, usages: KeyUsage[]) {
  const raw = fromBase64url(secret, 32);
  if (raw.length !== 32) throw new Error("A 256-bit key is required");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}
