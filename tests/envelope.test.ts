import { test, expect } from 'bun:test';
import { generateKey, seal, open, digestToken, equalDigest } from '../src';
import {
  acceptTrafficClientHello,
  createTrafficClientHello,
  openTraffic,
  sealTraffic,
} from '../src/traffic';
import { generateAssetKey, openAsset, sealAsset } from '../src/asset';
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

test('traffic sessions derive direction-separated keys, pad values and reject tampering', async () => {
  const client = await createTrafficClientHello();
  const server = await acceptTrafficClientHello(client.hello, 60_000);
  const clientKeys = await client.complete(server.welcome);
  const request = await sealTraffic({ operation: 7, name: 'private.txt' }, clientKeys, 'request');
  const opened = await openTraffic<{ operation: number; name: string }>(request, server.keys, 'request');
  expect(opened.value).toEqual({ operation: 7, name: 'private.txt' });
  expect(opened.packetId).toBeString();
  expect(request.length).toBeGreaterThan(300);
  const response = await sealTraffic({ ok: true }, server.keys, 'response');
  expect((await openTraffic<{ ok: boolean }>(response, clientKeys, 'response')).value).toEqual({ ok: true });
  await expect(openTraffic(request, server.keys, 'response')).rejects.toThrow();
  await expect(openTraffic(request.slice(0, -3) + 'AAA', server.keys, 'request')).rejects.toThrow();
});

test('separate traffic handshakes cannot read each other and packets expire', async () => {
  const first = await createTrafficClientHello();
  const firstServer = await acceptTrafficClientHello(first.hello, 60_000);
  const firstKeys = await first.complete(firstServer.welcome);
  const second = await createTrafficClientHello();
  const secondServer = await acceptTrafficClientHello(second.hello, 60_000);
  const packet = await sealTraffic('secret', firstKeys, 'request', 1);
  await expect(openTraffic(packet, secondServer.keys, 'request')).rejects.toThrow();
  await Bun.sleep(5);
  await expect(openTraffic(packet, firstServer.keys, 'request')).rejects.toThrow();
});

test('encrypted build assets require the build key and context', async () => {
  const key = generateAssetKey();
  const source = 'export const hiddenOperation = "fileshare/private";';
  const encrypted = await sealAsset(source, key, 'fileshare:test-build');
  const second = await sealAsset(source, key, 'fileshare:test-build');
  expect(second).not.toBe(encrypted);
  expect(encrypted).not.toContain('hiddenOperation');
  expect(await openAsset(encrypted, key, 'fileshare:test-build')).toBe(source);
  await expect(openAsset(encrypted, generateAssetKey(), 'fileshare:test-build')).rejects.toThrow();
  await expect(openAsset(encrypted, key, 'fileshare:other-build')).rejects.toThrow();
});
