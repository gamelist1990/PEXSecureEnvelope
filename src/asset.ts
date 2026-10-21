import { base64url, fromBase64url, importAesKey, randomBytes, text, utf8 } from "./codec";

const MAX_ASSET_BYTES = 16 * 1024 * 1024;

export function generateAssetKey() {
  return base64url(randomBytes(32));
}

export async function sealAsset(source: string, secret: string, context: string) {
  if (!context || context.length > 200) throw new Error("Invalid asset context");
  const clear = utf8(source);
  if (clear.length > MAX_ASSET_BYTES) throw new Error("Asset is too large");
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: utf8("pex-asset:v1:" + context),
      tagLength: 128,
    },
    await importAesKey(secret, ["encrypt"]),
    clear,
  );
  return `a1.${base64url(iv)}.${base64url(encrypted)}`;
}

export async function openAsset(envelope: string, secret: string, context: string) {
  try {
    if (!context || envelope.length > MAX_ASSET_BYTES * 2) throw new Error();
    const [version, encodedIv, encodedBody, extra] = envelope.split(".");
    if (version !== "a1" || !encodedIv || !encodedBody || extra) throw new Error();
    const iv = fromBase64url(encodedIv, 12);
    if (iv.length !== 12) throw new Error();
    const clear = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: utf8("pex-asset:v1:" + context),
        tagLength: 128,
      },
      await importAesKey(secret, ["decrypt"]),
      fromBase64url(encodedBody, MAX_ASSET_BYTES + 16),
    );
    return text(clear);
  } catch {
    throw new Error("Invalid encrypted asset");
  }
}
