# SubVet ロードマップ

*診断の幅を広げる*

---

## Phase 1: フィンガープリント拡充 (v0.2.0)

### 目標: 48 → 100+ サービス対応

**追加候補（テイクオーバー実績あり）:**

| カテゴリ | サービス | CNAME | 優先度 |
|----------|----------|-------|--------|
| **CDN/Edge** | Cloudflare Pages | `*.pages.dev` | 🔴 高 |
| | Amazon CloudFront | `*.cloudfront.net` | 🔴 高 |
| | KeyCDN | `*.kxcdn.com` | 🟡 中 |
| | StackPath | `*.stackpathcdn.com` | 🟡 中 |
| | Imperva/Incapsula | `*.incapdns.net` | 🟡 中 |
| **Serverless** | AWS Lambda URLs | `*.lambda-url.*.on.aws` | 🔴 高 |
| | AWS API Gateway | `*.execute-api.*.amazonaws.com` | 🔴 高 |
| | Cloudflare Workers | `*.workers.dev` | 🔴 高 |
| **コンテナ** | AWS App Runner | `*.awsapprunner.com` | 🟡 中 |
| | Google Cloud Run | `*.run.app` | 🟡 中 |
| | Digital Ocean App | `*.ondigitalocean.app` | 🟡 中 |
| **ストレージ** | Backblaze B2 | `*.backblazeb2.com` | 🟢 低 |
| | Wasabi | `*.wasabisys.com` | 🟢 低 |
| **国産SaaS** | さくらクラウド | `*.sakuraweb.com` | 🟡 中 |
| | ConoHa | `*.conoha.io` | 🟢 低 |
| **開発ツール** | Gitbook | `*.gitbook.io` | 🟡 中 |
| | Notion Sites | `*.notion.site` | 🔴 高 |
| | Hashnode | `*.hashnode.dev` | 🟡 中 |
| | dev.to (Forem) | `*.forem.com` | 🟢 低 |
| **フォーム/調査** | Typeform | `*.typeform.com` | 🟡 中 |
| | Tally | `*.tally.so` | 🟢 低 |
| | JotForm | `*.jotform.com` | 🟢 低 |
| **メール/マーケ** | Mailchimp Pages | `*.mailchimpsites.com` | 🟡 中 |
| | SendGrid Pages | `*.sendgrid.net` | 🟡 中 |
| | Postmark | `*.postmarkapp.com` | 🟢 低 |
| **分析/モニタ** | Datadog | `*.datadoghq.com` | 🟢 低 |
| | LogRocket | `*.logrocket.io` | 🟢 低 |
| **ヘルプデスク** | Help Scout | `*.helpscoutdocs.com` | 🟡 中 |
| | Groove | `*.groovehq.com` | 🟢 低 |
| **予約/決済** | Calendly | `*.calendly.com` | 🟢 低 |
| | Acuity | `*.acuityscheduling.com` | 🟢 低 |
| **動画** | Wistia | `*.wistia.com` | 🟢 低 |
| | Vimeo OTT | `*.vhx.tv` | 🟢 低 |

---

## Phase 2: 検出方式の多様化 (v0.3.0)

### 現状: CNAME + HTTP のみ
### 目標: 5種類の検出メカニズム

#### 2.1 NS Delegation チェック
```typescript
// ゾーン委任先が存在しない場合
subvet scan --check-ns
// NS: ns1.deadservice.com → NXDOMAIN
```

**対象例:**
- DNSimple, DNS Made Easy, NS1 等の委任
- Cloudflare zones (削除済み)
- Route53 hosted zones

#### 2.2 MX Record チェック
```typescript
// メールサーバー設定の乗っ取り
subvet scan --check-mx
// MX: mail.deadservice.com → NXDOMAIN
```

**リスク:**
- メール受信の乗っ取り（より深刻）
- パスワードリセットメールの傍受

#### 2.3 TXT/SPF Record 分析
```typescript
// SPF include先が無効
subvet scan --check-spf
// include:spf.deadservice.com → NXDOMAIN
```

**リスク:**
- SPF bypass によるフィッシング

#### 2.4 SRV Record チェック
```typescript
// サービスディスカバリの乗っ取り
subvet scan --check-srv
// _autodiscover._tcp → NXDOMAIN
```

#### 2.5 AAAA Record (IPv6) チェック
```typescript
// IPv6 専用サービスの検出
subvet scan --check-ipv6
```

---

## Phase 3: アクティブ検証 (v0.4.0)

### 3.1 Passive → Active モード
```bash
# デフォルト: パッシブ（安全）
subvet scan targets.txt

# アクティブ: 実際にテイクオーバー試行
subvet scan targets.txt --active --dry-run
```

### 3.2 自動PoC生成
```json
{
  "status": "vulnerable",
  "service": "AWS S3",
  "poc": {
    "command": "aws s3 mb s3://target-bucket --region us-east-1",
    "estimated_cost": "$0.00",
    "reversible": true
  }
}
```

### 3.3 証拠スクリーンショット
```bash
subvet scan --screenshot
# 404ページのスクリーンショットを保存
```

---

## Phase 4: エンタープライズ機能 (v0.5.0)

### 4.1 継続監視モード
```bash
# デーモンモード
subvet watch -f targets.txt --interval 6h --webhook https://...

# cron統合
subvet scan -f targets.txt --diff /var/lib/subvet/last.json
```

### 4.2 レポート出力
```bash
# HTML レポート
subvet scan -f targets.txt --report html -o report.html

# PDF レポート（監査用）
subvet scan -f targets.txt --report pdf --template enterprise
```

### 4.3 アラート連携
```bash
# Slack
subvet scan --alert slack --webhook $SLACK_WEBHOOK

# PagerDuty
subvet scan --alert pagerduty --routing-key $PD_KEY

# SIEM (Splunk/Datadog)
subvet scan --siem splunk --hec-url $HEC_URL
```

### 4.4 CI/CD 統合強化
```yaml
# GitHub Actions
- uses: taku-tez/subvet-action@v1
  with:
    targets: subdomains.txt
    fail-on: vulnerable
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

---

## Phase 5: サブドメイン列挙統合 (v0.6.0)

### 5.1 ビルトイン列挙
```bash
# パッシブ列挙
subvet enum example.com --passive

# アクティブ列挙（ブルートフォース）
subvet enum example.com --wordlist common.txt

# 自動パイプライン
subvet enum example.com | subvet scan --stdin
```

### 5.2 データソース統合
- Certificate Transparency (crt.sh)
- VirusTotal
- SecurityTrails
- Shodan
- Chaos (ProjectDiscovery)

### 5.3 履歴データ
```bash
# 過去のサブドメインも検出
subvet enum example.com --historical
# Wayback Machine, DNS履歴等
```

---

## Phase 6: 高度な分析 (v1.0.0)

### 6.1 組織全体スキャン
```bash
# ASN からドメイン自動検出
subvet org --asn AS12345

# 関連ドメイン自動検出
subvet org --seed example.com --depth 2
```

### 6.2 リスクスコアリング
```json
{
  "subdomain": "shop.example.com",
  "risk_score": 9.5,
  "factors": {
    "service_popularity": "high",
    "business_impact": "e-commerce",
    "exploit_difficulty": "trivial",
    "data_exposure": "customer_pii"
  }
}
```

### 6.3 自動修復提案
```json
{
  "remediation": {
    "option_1": {
      "action": "Remove CNAME record",
      "command": "aws route53 change-resource-record-sets ...",
      "risk": "low"
    },
    "option_2": {
      "action": "Reclaim the service",
      "steps": ["Create S3 bucket", "Upload index.html"],
      "risk": "medium"
    }
  }
}
```

---

## マイルストーン

| バージョン | リリース目標 | 主要機能 |
|-----------|-------------|----------|
| v0.2.0 | 2週間後 | 100+フィンガープリント |
| v0.3.0 | 1ヶ月後 | NS/MX/SPF検出 |
| v0.4.0 | 6週間後 | アクティブ検証、PoC生成 |
| v0.5.0 | 2ヶ月後 | 監視、レポート、アラート |
| v0.6.0 | 3ヶ月後 | サブドメイン列挙統合 |
| v1.0.0 | 4ヶ月後 | 組織スキャン、リスクスコア |

---

## 競合との差別化

| 機能 | SubVet | subjack | nuclei | dnsreaper |
|------|--------|---------|--------|-----------|
| フィンガープリント数 | 100+ | 30 | 50+ | 40 |
| NS/MX/SPF | ✅ | ❌ | 一部 | ❌ |
| アクティブPoC | ✅ | ❌ | ❌ | ❌ |
| 日本語レポート | ✅ | ❌ | ❌ | ❌ |
| CI統合 | ✅ | 一部 | ✅ | 一部 |
| 継続監視 | ✅ | ❌ | ❌ | ❌ |
| サブドメイン列挙 | ✅ | ❌ | 別ツール | ❌ |

---

## 優先実装（今週〜）

1. **Cloudflare Pages** フィンガープリント追加（利用者多い）
2. **AWS CloudFront** フィンガープリント追加（誤設定多い）
3. **Notion Sites** フィンガープリント追加（最近人気）
4. **NS delegation** チェック機能（検出の幅が大幅拡大）
5. **--diff** オプション（差分検出、CI向け）

---

*更新: 2026-02-03*
