import { base64url, concat, fromBase64url, randomBytes, text, utf8 } from "./codec";

export type TrafficHello = { v: 1; publicKey: string; nonce: string };
export type TrafficWelcome = {
  v: 1;
  sessionId: string;
  publicKey: string;
  nonce: string;
  expiresAt: number;
};
export type TrafficKeys = {
  sessionId: string;
  requestKey: CryptoKey;
  responseKey: CryptoKey;
  expiresAt: number;
};
export type TrafficDirection = "request" | "response";

const VERSION = 1;
const MAX_PACKET_BYTES = 2 * 1024 * 1024;
const PADDING_BUCKETS = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152];

async function createPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

async function exportPublic(key: CryptoKey) {
  return base64url(await crypto.subtle.exportKey("raw", key));
}

async function importPublic(encoded: string) {
  const raw = fromBase64url(encoded, 65);
  if (raw.length !== 65 || raw[0] !== 4) throw new Error("Invalid traffic public key");
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function deriveKeys(
  privateKey: CryptoKey,
  peerPublic: string,
  clientNonce: Uint8Array,
  serverNonce: Uint8Array,
  sessionId: string,
  expiresAt: number,
): Promise<TrafficKeys> {
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: await importPublic(peerPublic) },
    privateKey,
    256,
  );
  const keyMaterial = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: concat(clientNonce, serverNonce),
        info: utf8(`pex-traffic:v1:${sessionId}`),
      },
      keyMaterial,
      512,
    ),
  );
  return {
    sessionId,
    requestKey: await crypto.subtle.importKey("raw", bits.subarray(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]),
    responseKey: await crypto.subtle.importKey("raw", bits.subarray(32), "AES-GCM", false, ["encrypt", "decrypt"]),
    expiresAt,
  };
}

export async function createTrafficClientHello() {
  const pair = await createPair();
  const nonce = randomBytes(32);
  const hello: TrafficHello = {
    v: VERSION,
    publicKey: await exportPublic(pair.publicKey),
    nonce: base64url(nonce),
  };
  return {
    hello,
    complete: async (welcome: TrafficWelcome) => {
      if (
        welcome?.v !== VERSION ||
        !welcome.sessionId ||
        welcome.sessionId.length > 100 ||
        !Number.isSafeInteger(welcome.expiresAt) ||
        welcome.expiresAt <= Date.now()
      )
        throw new Error("Invalid traffic welcome");
      const serverNonce = fromBase64url(welcome.nonce, 32);
      if (serverNonce.length !== 32) throw new Error("Invalid traffic welcome");
      return deriveKeys(pair.privateKey, welcome.publicKey, nonce, serverNonce, welcome.sessionId, welcome.expiresAt);
    },
  };
}

export async function acceptTrafficClientHello(hello: TrafficHello, ttlMs = 15 * 60_000) {
  if (hello?.v !== VERSION || !Number.isSafeInteger(ttlMs) || ttlMs < 10_000 || ttlMs > 3_600_000)
    throw new Error("Invalid traffic hello");
  const clientNonce = fromBase64url(hello.nonce, 32);
  if (clientNonce.length !== 32) throw new Error("Invalid traffic hello");
  const pair = await createPair();
  const serverNonce = randomBytes(32);
  const sessionId = base64url(randomBytes(18));
  const expiresAt = Date.now() + ttlMs;
  const welcome: TrafficWelcome = {
    v: VERSION,
    sessionId,
    publicKey: await exportPublic(pair.publicKey),
    nonce: base64url(serverNonce),
    expiresAt,
  };
  return {
    welcome,
    keys: await deriveKeys(pair.privateKey, hello.publicKey, clientNonce, serverNonce, sessionId, expiresAt),
  };
}

function keyFor(keys: TrafficKeys, direction: TrafficDirection) {
  if (keys.expiresAt <= Date.now()) throw new Error("Traffic session expired");
  return direction === "request" ? keys.requestKey : keys.responseKey;
}

function paddedLength(length: number) {
  for (const bucket of PADDING_BUCKETS) if (length <= bucket) return bucket;
  throw new Error("Traffic value is too large");
}

export async function sealTraffic(
  value: unknown,
  keys: TrafficKeys,
  direction: TrafficDirection,
  ttlMs = 60_000,
) {
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 300_000)
    throw new Error("Invalid traffic lifetime");
  const json = utf8(JSON.stringify({ v: VERSION, expiresAt: Date.now() + ttlMs, value }));
  const length = json.length + 4;
  const clear = randomBytes(paddedLength(length));
  new DataView(clear.buffer).setUint32(0, json.length);
  clear.set(json, 4);
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: utf8(`pex-traffic:v1:${keys.sessionId}:${direction}`),
      tagLength: 128,
    },
    await keyFor(keys, direction),
    clear,
  );
  return `t1.${base64url(iv)}.${base64url(encrypted)}`;
}

export async function openTraffic<T>(
  packet: string,
  keys: TrafficKeys,
  direction: TrafficDirection,
): Promise<{ value: T; packetId: string }> {
  try {
    if (packet.length > MAX_PACKET_BYTES * 2) throw new Error();
    const [version, encodedIv, encodedBody, extra] = packet.split(".");
    if (version !== "t1" || !encodedIv || !encodedBody || extra) throw new Error();
    const iv = fromBase64url(encodedIv, 12);
    if (iv.length !== 12) throw new Error();
    const clear = new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: utf8(`pex-traffic:v1:${keys.sessionId}:${direction}`),
          tagLength: 128,
        },
        await keyFor(keys, direction),
        fromBase64url(encodedBody, MAX_PACKET_BYTES + 16),
      ),
    );
    if (clear.length < 4) throw new Error();
    const length = new DataView(clear.buffer, clear.byteOffset, clear.byteLength).getUint32(0);
    if (length < 2 || length > clear.length - 4) throw new Error();
    const payload = JSON.parse(text(clear.subarray(4, 4 + length)));
    if (payload?.v !== VERSION || !Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= Date.now())
      throw new Error();
    return { value: payload.value as T, packetId: encodedIv };
  } catch {
    throw new Error("Invalid or expired traffic packet");
  }
}
