# SubVet Phase 2 - 検出方式の多様化

*作成: 2026-02-03 19:10*

---

## 目標
CNAMEだけでなく、NS/MX/SPF/SRV/AAAAもチェックして検出の幅を広げる

---

## タスク一覧

### 1. MX Dangling チェック ✅ 完了
- [x] types.ts に `mx_nxdomain` 追加
- [x] dns.ts に `resolveMx` 機能追加
- [x] scanner.ts でMXチェック統合
- [x] cli.ts に `--check-mx` オプション追加
- [ ] テスト追加

**リスク:**
- MX乗っ取りはCNAMEより深刻
- メール傍受、パスワードリセットメール受信可能

### 2. SPF Include チェック ✅ 完了
- [x] types.ts に `spf_include_nxdomain` 追加
- [x] dns.ts に `resolveTxt` + SPFパース機能追加
- [x] scanner.ts でSPFチェック統合
- [x] cli.ts に `--check-spf` オプション追加
- [ ] テスト追加

**リスク:**
- SPFバイパスでフィッシングメール送信可能

### 3. テストコード追加 (vitest) ✅ 完了
- [x] `src/__tests__/dns.test.ts` 作成 (8 tests)
- [ ] `src/__tests__/scanner.test.ts` 作成
- [x] `src/__tests__/fingerprints.test.ts` 作成 (13 tests)
- [x] CI用 npm script (既存)
- [ ] カバレッジ設定

### 4. SRV Record チェック ✅ 完了
- [x] types.ts に `srv_nxdomain` 追加
- [x] dns.ts に `resolveSrv` 機能追加
- [x] `_autodiscover._tcp` 等の一般的なSRVチェック
- [ ] テスト追加

### 5. AAAA (IPv6) チェック強化 ✅ 完了
- [x] IPv6専用サービスの検出改善
- [x] IPv4/IPv6フラグ追加 (hasIpv4/hasIpv6)
- [ ] テスト追加

---

## 進捗

| タスク | 開始 | 完了 | 状態 |
|--------|------|------|------|
| 1. MX | 19:10 | 19:12 | ✅ |
| 2. SPF | 21:08 | 21:13 | ✅ |
| 3. テスト | 21:11 | 21:13 | ✅ (21 tests) |
| 4. SRV | 21:13 | 21:15 | ✅ |
| 5. AAAA | 21:15 | 21:16 | ✅ |

---

## 実装メモ

### MX Dangling の検出ロジック
```typescript
// 1. MXレコード取得
const mxRecords = await resolveMx(domain);

// 2. 各MXホストが解決できるか確認
for (const mx of mxRecords) {
  const isDangling = await isHostDangling(mx.exchange);
  if (isDangling) {
    // 脆弱性報告
  }
}
```

### SPF Include の検出ロジック
```typescript
// 1. TXTレコードからSPF取得
const txtRecords = await resolveTxt(domain);
const spf = txtRecords.find(r => r.startsWith('v=spf1'));

// 2. includeディレクティブを抽出
const includes = spf.match(/include:(\S+)/g);

// 3. 各include先が解決できるか確認
for (const include of includes) {
  const target = include.replace('include:', '');
  const isDangling = await isHostDangling(target);
}
```
