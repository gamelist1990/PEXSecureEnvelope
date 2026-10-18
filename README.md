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
