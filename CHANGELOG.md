# Changelog

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
