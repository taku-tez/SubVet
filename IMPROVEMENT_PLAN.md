# SubVet 改善計画 - 競合OSS比較に基づく分析

> 作成日: 2026-02-08
> 調査対象: subjack, Subdominator, dnsReaper, BadDNS, can-i-take-over-xyz, nuclei templates

## 競合比較サマリー

| 機能 | SubVet | subjack | Subdominator | dnsReaper | BadDNS |
|------|--------|---------|-------------|-----------|--------|
| フィンガープリント数 | 88 | ~30 | 不明(バイナリ) | 58 | 114 |
| 言語 | TypeScript | Go | C# | Python | Python |
| Confidence scoring | ✅ (0-10) | ❌ | ❌ | ✅ (3段階) | ❌ |
| Negative patterns | ✅ | ❌ | ❌ | ❌ | ❌ |
| NS/MX/SPF/SRV checks | ✅ | ❌ | ❌ | ❌ | ✅ |
| NSEC walking | ❌ | ❌ | ❌ | ❌ | ✅ |
| Zone transfer check | ❌ | ❌ | ❌ | ❌ | ✅ |
| HTML references check | ❌ | ❌ | ❌ | ❌ | ✅ |
| TXT record check | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cloud provider直接連携 | ❌ | ❌ | ❌ | ✅ (AWS/Azure/CF) | ❌ |
| Takeover検証(validation) | ❌ | ❌ | ✅ (--validate) | ❌ | ❌ |
| Docker配布 | ❌ | ❌ | ❌ | ✅ | ❌ |
| CI/CD diff mode | ✅ | ❌ | ❌ | ✅ (exit code) | ❌ |
| YAML署名ファイル | ❌ (TS埋め込み) | JSON | ❌ | Python埋め込み | ✅ YAML |
| BBOT統合 | ❌ | ❌ | ❌ | ❌ | ✅ |
| Slack webhook | ✅ | ❌ | ❌ | ❌ | ❌ |
| レポート出力 | ✅ (JSON/MD/HTML) | JSON/TXT | TXT | CSV/JSON | ❌ |

---

## 🔴 優先度高（すぐやるべき）

### 1. フィンガープリントをYAML外部ファイル化
**なぜ重要**: 現在88サービスがTypeScriptにハードコードされており、ユーザーがカスタム署名を追加できない。コミュニティ貢献のハードルも高い。
**実装ツール**: BadDNS (YAML), subjack (JSON), nuclei templates (YAML)
**難易度**: 中 (2-3日)
**詳細**:
- BadDNSのYAML構造を参考に `signatures/` ディレクトリへ移行
- 既存のTS fingerprints→YAML自動変換スクリプト作成
- `--custom-signatures` オプション追加（BadDNS互換）
- 後方互換のため既存TSも読めるようにする

### 2. Takeover検証（Validation）機能
**なぜ重要**: フィンガープリントマッチだけでは誤検知が残る。実際にサービス側APIを叩いてドメインが本当にclaimable かを確認する機能は検出精度を大幅に上げる。
**実装ツール**: Subdominator (`--validate` フラグ)
**難易度**: 高 (1-2週間、サービスごとに個別実装)
**詳細**:
- S3バケット存在チェック、GitHub Pages CNAME確認等
- 検証成功→confidence +3、検証失敗→confidence -5 のようなスコア調整
- まずはAWS S3, GitHub Pages, Azure等の主要5サービスから

### 3. HTMLリファレンスチェック（Dangling References）
**なぜ重要**: CNAME以外の攻撃ベクトル。HTMLページ内のscript src, link href等が指すドメインがテイクオーバー可能な場合、XSS等に直結する。
**実装ツール**: BadDNS (`references` モジュール)
**難易度**: 中 (3-5日)
**詳細**:
- HTTPレスポンスボディからURL抽出
- 抽出ドメインのDNS解決＋登録可能性チェック
- Supply chain attack検出として差別化

### 4. TXTレコードチェック
**なぜ重要**: TXTレコード内のドメイン参照（Google site verification, DKIM等）もテイクオーバーの対象になりうる。
**実装ツール**: BadDNS (`txt` モジュール)
**難易度**: 低 (1-2日)
**詳細**:
- 既存のDNSリゾルバにTXTクエリ追加
- TXT値からドメイン抽出→解決チェック

---

## 🟡 優先度中（次のフェーズ）

### 5. クラウドプロバイダー直接連携
**なぜ重要**: ファイルベースの入力だけでなく、AWS Route53/Cloudflare/Azure DNSから直接レコードを取得できれば、企業ユーザーの導入が格段に楽になる。
**実装ツール**: dnsReaper (AWS Route53, Cloudflare, Azure DNS)
**難易度**: 高 (各プロバイダー2-3日)
**詳細**:
- `subvet scan --aws --profile production` のようなインターフェース
- AWS SDK/Cloudflare API/Azure SDKを利用
- 全ゾーンの全レコードを自動取得→スキャン

### 6. Docker / コンテナ配布
**なぜ重要**: CI/CDパイプラインでの利用やクイックスタートに必須。
**実装ツール**: dnsReaper (Docker Hub公開)
**難易度**: 低 (半日)
**詳細**:
- `Dockerfile` + GitHub Actions自動ビルド
- `docker run subvet scan -f /data/domains.txt`

### 7. GitHub Actions公式アクション
**なぜ重要**: DevSecOpsワークフローへの統合。PR時にサブドメインテイクオーバーチェックを自動実行。
**実装ツール**: dnsReaper (exit code活用), SubVet既存diff mode活用
**難易度**: 低-中 (1-2日)
**詳細**:
- `action.yml` 作成、GitHub Marketplaceに公開
- 既存 `--diff` モードと組み合わせ
- PR commentにサマリー出力

### 8. NSEC Walking / Zone Transfer検出
**なぜ重要**: DNS misconfiguration全般をカバーするツールとしてのポジショニング。NSECウォークはサブドメイン列挙手法として知名度が高い。
**実装ツール**: BadDNS (`nsec`, `zonetransfer` モジュール)
**難易度**: 中 (3-5日)
**詳細**:
- NSEC/NSEC3レコードを辿ってサブドメインを列挙
- Zone transfer (AXFR) 試行

### 9. SARIF出力フォーマット
**なぜ重要**: GitHub Code Scanningへの直接統合。セキュリティアラートとしてGitHub UI上に表示される。
**実装ツール**: nuclei (SARIF出力対応)
**難易度**: 低 (1日)
**詳細**:
- SARIF 2.1.0スキーマ準拠の出力
- `--report sarif` オプション追加

### 10. フィンガープリント自動更新チェック
**なぜ重要**: can-i-take-over-xyzやnuclei templatesは頻繁に更新される。SubVetのfingerprintが古くなるリスクがある。
**実装ツール**: can-i-take-over-xyz (コミュニティDB)
**難易度**: 中 (2-3日)
**詳細**:
- `subvet update-signatures` コマンド
- can-i-take-over-xyz / nuclei templates からの差分取得
- 新サービス検出時の通知

---

## 🟢 優先度低（将来検討）

### 11. Webダッシュボード / Web UI
**なぜ重要**: non-technical ステークホルダーへの報告用。現状HTML reportはあるがインタラクティブではない。
**実装ツール**: dnsReaper (簡易Web版あり)
**難易度**: 高 (1-2週間)

### 12. BBOT / サブドメイン列挙ツール統合
**なぜ重要**: subfinder/amass/bbot等との深い統合で、列挙→チェックのワンストップ体験を提供。
**実装ツール**: BadDNS (BBOTモジュール)
**難易度**: 中

### 13. DNS over HTTPS (DoH) / DNS over TLS (DoT)
**なぜ重要**: 企業ネットワークでのDNS制限回避、プライバシー向上。
**実装ツール**: dnsx (DoH対応)
**難易度**: 中 (2-3日)

### 14. Wildcard DNS検出
**なぜ重要**: ワイルドカードDNS設定されたドメインでの誤検知排除。ランダムサブドメインへの応答をチェック。
**実装ツール**: Subdominator (公開サフィックスリスト活用), subjack
**難易度**: 低 (1日)

### 15. リトライ / レジリエンス
**なぜ重要**: 大量スキャン時のDNSレート制限やタイムアウトへの耐性。
**実装ツール**: 複数ツールが実装
**難易度**: 低 (1日)
**詳細**:
- 指数バックオフリトライ
- DNSサーバーローテーション
- 失敗ドメインの再スキャンキュー

### 16. WHOIS / ドメイン登録可能性チェック
**なぜ重要**: NXDOMAINのCNAMEターゲットが登録可能かをWHOIS/ドメインAPIで確認すると精度が上がる。
**実装ツール**: subjack (NXDOMAIN + 登録可能チェック)
**難易度**: 中

### 17. Jira / PagerDuty / Teams Webhook
**なぜ重要**: Slack以外のアラート先。企業環境ではTeamsやJiraが多い。
**実装ツール**: (独自)
**難易度**: 低 (各1日)

---

## SubVetの既存の強み（維持すべき点）

1. **Confidence Scoring (0-10)** - dnsReaperは3段階のみ、他は非対応。SubVetの重み付きスコアリングは優れている
2. **Negative Patterns** - 他ツールにない独自機能。FP削減に大きく貢献
3. **CI/CD diff mode** - dnsReaperのexit codeより高度。ベースライン比較は実用的
4. **HTML/Markdownレポート** - 他ツールより充実した出力フォーマット
5. **MX/SPF/SRV/NS全チェック** - BadDNS以外にない包括的DNS検査
6. **264テスト** - テストカバレッジは競合中トップクラス

---

## 実装ロードマップ案

### Phase 1 (v0.11) - 2週間
- [ ] YAML署名ファイル化 (#1)
- [ ] TXTレコードチェック (#4)
- [ ] Docker配布 (#6)
- [ ] Wildcard DNS検出 (#14)

### Phase 2 (v0.12) - 3週間
- [ ] Takeover検証機能 (#2)
- [ ] HTMLリファレンスチェック (#3)
- [ ] GitHub Actions (#7)
- [ ] SARIF出力 (#9)

### Phase 3 (v0.13) - 4週間
- [ ] クラウドプロバイダー連携 (#5)
- [ ] NSEC Walking (#8)
- [ ] フィンガープリント自動更新 (#10)
- [ ] リトライ / レジリエンス (#15)
