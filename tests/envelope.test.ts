import { test, expect } from 'bun:test';
import { generateKey, seal, open, digestToken, equalDigest } from '../src';
test('round trip, nonce uniqueness, key and purpose separation, tamper rejection', async () => {
  const key = generateKey(), token = await seal({ id: 1 }, key, 'test');
  expect(await open(token, key, 'test')).toEqual({ id: 1 });
  expect(await seal({ id: 1 }, key, 'test')).not.toBe(token);
  await expect(open(token, generateKey(), 'test')).rejects.toThrow();
  await expect(open(token, key, 'other')).rejects.toThrow();
  await expect(open(token.slice(0, -5) + 'AAAAA', key, 'test')).rejects.toThrow();
  expect(equalDigest(digestToken('a'), digestToken('a'))).toBe(true);
  expect(equalDigest(digestToken('a'), digestToken('b'))).toBe(false);
});
test('expired envelope', async () => {
  const key = generateKey(), token = await seal({}, key, 'test', 1);
  await Bun.sleep(5);
  await expect(open(token, key, 'test')).rejects.toThrow();
});
