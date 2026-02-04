# Changelog

## v0.8.0 (2026-02-04)

### 🚀 New Features

**Slack Webhook Integration** (`--slack-webhook`)
- Send scan results and diff reports to Slack
- Rich formatting with Block Kit (headers, fields, emojis)
- Configurable notification conditions via `--slack-on`:
  - `always`: Notify on every scan
  - `issues`: Notify when any issues found (default)
  - `new`: Notify only on new vulnerable/likely findings
- Works with both regular scans and diff mode

### Usage Examples

```bash
# Notify Slack on any issues
subvet scan -f subdomains.txt --slack-webhook $SLACK_WEBHOOK

# Notify only on new vulnerabilities (CI mode)
subvet scan -f subdomains.txt --diff baseline.json \
  --slack-webhook $SLACK_WEBHOOK --slack-on new

# Always notify (for monitoring dashboards)
subvet scan example.com --slack-webhook $SLACK_WEBHOOK --slack-on always
```

### Tests
- 251 tests (249 passed, 2 skipped)
- 11 new Slack module tests added

---

## v0.7.0 (2026-02-04)

### 🚀 New Features

**CI/CD Diff Mode** (`--diff`)
- Compare current scan against a baseline JSON file
- Detect new vulnerabilities, resolved issues, and status changes
- Exit codes optimized for CI pipelines:
  - `0`: No new vulnerabilities (OK to proceed)
  - `1`: New likely vulnerabilities (warning)
  - `2`: New confirmed vulnerabilities (fail)
- `--diff-json` option for JSON output
- Human-readable diff report with severity sorting

### Usage Examples

```bash
# Save baseline
subvet scan -f subdomains.txt -o baseline.json

# Later: compare against baseline
subvet scan -f subdomains.txt --diff baseline.json

# CI pipeline with JSON output
subvet scan -f subdomains.txt --diff baseline.json --diff-json
echo "Exit code: $?"
```

### Tests
- 238 tests (236 passed, 2 skipped)
- 16 new diff module tests added

---

## v0.6.2 (2026-02-04)

### 🐛 Bug Fixes

**指紋ルール型の実装** (FB #2)
- `checkDnsFingerprints()` に `ns_nxdomain`, `mx_nxdomain`, `spf_include_nxdomain`, `srv_nxdomain` を追加
- `nsDangling`, `mxDangling`, `spfDangling`, `srvDangling` 配列に基づいて評価
- 各ルールマッチ時に evidence を追加

### Tests
- 222 tests (220 passed, 2 skipped)
- DNS dangling fingerprint rule テスト4件追加

---

## v0.6.1 (2026-02-04)

### 🚀 Performance Improvements

1. **DNS解決の並列化**
   - A/AAAA レコードを `Promise.allSettled()` で並列取得
   - CNAME ターゲットの A/AAAA も並列化
   - 約2倍の速度向上

2. **ダングリングチェックの並列化**
   - NS/MX/SPF/SRV チェックを `Promise.all()` で並列実行
   - 各チェック内のターゲット解決も並列化
   - SRV プレフィックス（7種）の解決も並列化

3. **共通ロジックの抽出**
   - `targetResolves()` ヘルパーメソッド追加
   - `isNsDangling()`, `isMxDangling()`, `isSrvTargetDangling()`, `isCnameDangling()` を統一
   - 重複コード削減（dns.ts: 546→468行、-14%）

### Code Quality
- 型安全性向上（`Promise.allSettled` の戻り値型）
- エラーハンドリングの統一

---

## v0.6.0 (2026-02-04)

### 🚀 Improvements

1. **バージョン統一** (#1)
   - `package.json` を唯一のソースとして統一
   - `src/version.ts` モジュール追加
   - CLI, Scanner, HTTP User-Agent が全て同じバージョンを参照
   - READMEのJSON例も統一

2. **IPv6対応のダングリング判定** (#2)
   - `isNsDangling()` / `isMxDangling()` / `isSrvTargetDangling()` / `isCnameDangling()`
   - A レコードだけでなく AAAA レコードも確認
   - IPv6-only のターゲットを誤検知しなくなった

3. **NXDOMAIN判定の修正** (#2-2)
   - A レコードの ENOTFOUND 時点で nxdomain を設定しないように変更
   - A と AAAA の両方が ENOTFOUND かつ CNAME なしの場合のみ nxdomain = true
   - AAAA が存在するのに NXDOMAIN と誤判定される問題を修正

4. **SRV型定義追加** (#3)
   - `types.ts` の `DnsRecord.type` に `'SRV'` を追加
   - `dns.ts` の `as any` キャストを削除し型安全に

5. **CLI入力のドメイン検証** (#4)
   - `isValidDomain()` を `check` / `scan` コマンドで適用
   - ファイル/stdin からの入力も検証
   - `-v` オプションで無効ドメインをスキップ時に警告表示

6. **Markdownレポートの特殊文字エスケープ** (#5)
   - `|` (パイプ) を `\|` にエスケープ
   - 改行を `<br>` に変換
   - テーブル崩れ防止

7. **入力処理の統一** (#6)
   - `parseSubdomains()` を CLI 入力処理で利用
   - `readFromFile` / `readFromStdin` が統一された正規化ロジックを使用
   - trim, lowercase, コメント除去を一箇所に集約

### Tests
- 218 tests (216 passed, 2 skipped)
- version, DNS dangling, CLI validation, report escaping テスト追加

---

## v0.5.1 (2026-02-04)

### 🐛 Bug Fixes (FB対応 #2)

1. **CNAME解決ロジックの修正** (#1)
   - CNAMEが存在するだけでnxdomain=trueになる問題を修正
   - CNAMEチェーン追跡後、最終CNAMEのA/AAAAを確認
   - 最終CNAMEが解決できない場合のみnxdomain=true

2. **dns_nxdomainルールの証跡改善** (#2)
   - `checkDnsFingerprints()` でdns_nxdomainの証跡を追加
   - HTTPスキップ時でもDNS判定が残るように

3. **CNAME末尾ドット対応** (#3)
   - `normalizeDomain()` / `normalizeCname()` 追加
   - FQDNフォーマット（末尾.）を正規化
   - DNS解決時とfingerprint照合時の両方で正規化

4. **DNSエラーの反映改善** (#4)
   - タイムアウト/SERVFAILを`result.error`に記録
   - エラー握りつぶしを修正

### Tests
- 197 tests (195 passed, 2 skipped)
- CNAME末尾ドット、正規化テスト追加

## v0.5.0 (2026-02-04)

### 🐛 Bug Fixes (FB対応)

1. **DNS系フィンガープリント評価を追加** (#1)
   - `dns_nxdomain` / `dns_cname` ルールをスキャナーで評価
   - `checkDnsFingerprints()` メソッド追加
   - DNSフェーズでの脆弱性検知が機能するように

2. **DNSタイムアウトのタイマーリーク修正** (#2)
   - `withTimeout()` で `clearTimeout()` をfinally句で呼び出し
   - メモリリーク防止

3. **HTTPボディ読み込みの効率化** (#3)
   - `chunks.flatMap(c => [...c])` (O(n²)) を削除
   - `Uint8Array` の効率的な連結に置き換え
   - `maxBodySize` 到達時に早期キャンセル

4. **CLI数値オプション検証追加** (#4)
   - `timeout` / `concurrency` の `NaN` / 負数チェック
   - 不正値時にエラーメッセージを表示して終了

5. **CNAMEマッチのglob変換改善** (#5)
   - `*` / `?` / `.` を含む全メタ文字に対応
   - `escapeRegex` で先にエスケープ後、glob変換

### Tests
- 192 tests (190 passed, 2 skipped)
- DNS fingerprint evaluation test追加
- Glob pattern matching test追加

## v0.4.0 (2026-02-04)

### 🎯 Precision Improvements

Major overhaul of detection accuracy to reduce false positives.

#### New Features
- **Confidence scoring (0-10)** - Each detection now includes a confidence score
- **Required rules** - Fingerprints can mark rules as `required` (must match)
- **Rule weights** - Body matches weighted higher than status codes
- **Negative patterns** - Patterns that indicate NOT vulnerable (safe state)
- **Minimum confidence threshold** - Services can set `minConfidence` to filter low-quality matches

#### Fingerprint Improvements
- AWS S3: Added `AccessDenied` negative pattern (bucket exists)
- GitHub Pages: Requires body match, not just 404
- Heroku: Added `herokucdn.com/error-pages` pattern
- Vercel: Requires body match, added 200 status negative
- Shopify: Added active shop detection (Add to cart, checkout)
- CloudFront: Improved header detection, cache hit negative
- Fly.io: Now requires body pattern, not just 404
- Helprace: Complete rewrite (was only 301 status)

#### Generic Pattern Improvements
- Strong vs weak indicator classification
- Safe pattern detection (maintenance, coming soon, login pages)
- Compound matching (status + body required for weak indicators)

#### Detection Logic
- `vulnerable` status: confidence >= 7 + requiredMet
- `likely` status: confidence >= minConfidence + requiredMet
- `potential` status: low confidence or required not met
- `not_vulnerable` status: negative pattern matched

## v0.3.0 (2026-02-04)

### Features
- **80+ service fingerprints** - Major expansion from 48 to 80 services
- **NS delegation check** (`--check-ns`) - Detect dangling nameservers
- **MX record check** (`--check-mx`) - Detect dangling mail servers (critical risk)
- **SPF include check** (`--check-spf`) - Detect dangling SPF includes
- **SRV record check** (`--check-srv`) - Detect dangling SRV records (autodiscover, SIP, etc.)
- **IPv4/IPv6 flags** - Added `hasIpv4` and `hasIpv6` to DNS results
- **Summary mode** (`--summary`) - Quick summary output without full JSON

### Improvements
- **High-confidence detection** - HTTP body/header matches are prioritized over status code only
- **Status code only matches** - Now marked as "likely" instead of "vulnerable" to reduce false positives
- **Retry logic** - Added retry wrapper for DNS operations

### New Services Added
- Cloudflare Pages, AWS CloudFront, AWS Amplify
- Discourse, Ngrok, HatenaBlog
- Help Juice, Help Scout Docs, Gemfury
- JetBrains YouTrack, Readme.io, Pingdom
- SurveySparrow, Uberflip, UptimeRobot
- Worksites, Campaign Monitor, GetResponse
- SmartJobBoard, Helprace, Gitbook
- Hashnode, Framer, DigitalOcean App Platform
- Replit, Glitch, Carrd, Softr, Bubble
- Deta Space, Linear, Webnode, Notion Sites
- Google Cloud Run

### Tests
- 35 tests across 3 test files
- Coverage for DNS, scanner, and fingerprint modules

## v0.2.0 (2026-02-03)

### Initial Release
- 48 service fingerprints
- CNAME-based subdomain takeover detection
- HTTP probing with fingerprint matching
- JSON output format
- CI/CD friendly exit codes
