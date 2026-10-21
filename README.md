# PEX Secure Envelope

公開アルゴリズムとサーバーだけが持つランダム鍵を分離する、Bun/TypeScript向けの小さな暗号ライブラリです。AES-256-GCM、96-bitのランダムnonce、用途別AAD、有効期限、256-bitランダムトークンを使用します。独自暗号・Unicode難読化は使用しません。

```ts
import { generateKey, seal, open } from '@pexserver/secure-envelope';
const key = generateKey(); // 秘密管理基盤か0600のサーバー設定へ保存。ブラウザ・Gitへ渡さない
const ticket = await seal({ fileId: 'example' }, key, 'download-ticket', 60_000);
const payload = await open(ticket, key, 'download-ticket');
```

鍵は256-bit、用途contextは必須。改ざん・用途違い・期限切れは同じエラーで拒否します。鍵の更新時は古いenvelopeが失効します。トークンは一度だけ利用するなら、呼出側でjti/消費済み記録を管理してください。暗号化は認証・認可・TLS・レート制限の代わりにはなりません。

ソースが公開されても鍵を知らずに暗号文を偽造できない設計ですが、独立した暗号監査は未実施です。ブラウザへ送ったJavaScriptの本文を利用者から隠すことはできません。秘密の処理・鍵はサーバーへ置きます。HTTP通信にはTLSを別途使用してください。

検証: `bun test`。MIT License。

## ブラウザ通信エンベロープ

`@pexserver/secure-envelope/traffic` は、ブラウザとアプリケーションサーバー間でP-256 ECDHから方向別AES-256-GCM鍵を派生し、短命な認証付きパケットを作ります。平文長は段階的な固定サイズへパディングされます。受信側は返された `packetId` を短命セッション内で一度だけ受理し、リプレイを拒否してください。

```ts
import { createTrafficClientHello, acceptTrafficClientHello, sealTraffic, openTraffic } from '@pexserver/secure-envelope/traffic';
const client = await createTrafficClientHello();
const server = await acceptTrafficClientHello(client.hello);
const clientKeys = await client.complete(server.welcome);
const packet = await sealTraffic({ operation: 7 }, clientKeys, 'request');
const { value, packetId } = await openTraffic(packet, server.keys, 'request');
```

これはTLSの代替ではありません。HTTPSの内側でAPIの形と平文長を直接観測しにくくし、TLS終端とアプリケーションを分離する用途の追加層です。ブラウザを操作できる利用者は暗号化前・復号後の値を観測できます。

## 暗号化ビルド資産

`@pexserver/secure-envelope/asset` は、ビルド成果物をAES-256-GCMで暗号化します。鍵は成果物と一緒に公開せず、認証済み通信エンベロープなど別経路で短命に渡します。ブラウザは実行前に復号するため、これは静的収集や簡易解析のコストを上げる機能であり、クライアント所有者からコードを完全に秘匿する機能ではありません。
