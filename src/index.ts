/** Versioned AES-256-GCM envelopes. Algorithms are public; keys stay server-side. */
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
export const generateKey = () => randomBytes(32).toString('base64url');
export const randomToken = () => randomBytes(32).toString('base64url');
export const digestToken = (value: string) => createHash('sha256').update(value).digest('hex');
export function equalDigest(a: string, b: string): boolean {
  return a.length === 64 && b.length === 64 && /^[a-f0-9]+$/.test(a + b) && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
async function importKey(secret: string) {
  const bytes = Buffer.from(secret, 'base64url');
  if (bytes.length !== 32) throw new Error('A 256-bit key is required');
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function seal(value: unknown, secret: string, context: string, ttlMs = 300_000): Promise<string> {
  if (!context || !Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Invalid context or lifetime');
  const iv = randomBytes(12);
  const payload = Buffer.from(JSON.stringify({ expiresAt: Date.now() + ttlMs, value }));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: Buffer.from('pex-envelope:v1:' + context), tagLength: 128 }, await importKey(secret), payload);
  return 'v1.' + iv.toString('base64url') + '.' + Buffer.from(encrypted).toString('base64url');
}
export async function open<T>(envelope: string, secret: string, context: string): Promise<T> {
  try {
    if (!context || envelope.length > 1_048_576) throw new Error();
    const parts = envelope.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1' || !/^[\w-]+$/.test(parts[1] + parts[2])) throw new Error();
    const iv = Buffer.from(parts[1], 'base64url');
    if (iv.length !== 12) throw new Error();
    const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: Buffer.from('pex-envelope:v1:' + context), tagLength: 128 }, await importKey(secret), Buffer.from(parts[2], 'base64url'));
    const payload = JSON.parse(Buffer.from(clear).toString('utf8'));
    if (!Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= Date.now()) throw new Error();
    return payload.value as T;
  } catch { throw new Error('Invalid or expired envelope'); }
}

export { generateAssetKey, sealAsset, openAsset } from './asset';
export {
  createTrafficClientHello,
  acceptTrafficClientHello,
  sealTraffic,
  openTraffic,
} from './traffic';
export type {
  TrafficHello,
  TrafficWelcome,
  TrafficKeys,
  TrafficDirection,
} from './traffic';
