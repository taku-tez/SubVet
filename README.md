# SubVet 🔍

**Subdomain Takeover Vulnerability Scanner**

Fast, accurate subdomain takeover detection with 80+ service fingerprints, confidence scoring, and comprehensive DNS checks.

## Features

- 🎯 **80+ Service Fingerprints** - AWS, Azure, GCP, GitHub Pages, Heroku, Vercel, Shopify, and more
- 🧠 **Confidence Scoring** - Weighted rules reduce false positives
- 🔐 **DNS Security Checks** - NS/MX/SPF/SRV dangling detection
- ⚡ **Fast Concurrent Scanning** - Configurable parallelism
- 📊 **Multiple Output Formats** - JSON, Markdown, HTML reports
- 🛡️ **CNAME Chain Following** - Detect deeply nested dangling records

## Installation

```bash
npm install -g subvet
```

## Quick Start

```bash
# Check a single subdomain
subvet check shop.example.com

# Scan multiple subdomains
subvet scan -f subdomains.txt

# Pipe from other tools
subfinder -d example.com | subvet scan --stdin

# Generate HTML report
subvet scan -f targets.txt --report html > report.html
```

## Commands

### scan

Scan subdomains with JSON output (default).

```bash
subvet scan example.com
subvet scan -f targets.txt --concurrency 20
subvet scan --stdin < subdomains.txt
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file <path>` | Read subdomains from file | - |
| `--stdin` | Read from stdin | false |
| `-t, --timeout <ms>` | Request timeout | 10000 |
| `-c, --concurrency <n>` | Parallel requests | 10 |
| `--no-http` | Skip HTTP probing | false |
| `--check-ns` | Check NS delegation | false |
| `--check-mx` | Check MX records | false |
| `--check-spf` | Check SPF includes | false |
| `--check-srv` | Check SRV records | false |
| `--report <format>` | Output format (json/md/html) | json |
| `--summary` | Summary only | false |
| `--pretty` | Pretty print JSON | false |
| `-v, --verbose` | Show progress | false |

### check

Human-readable single subdomain check.

```bash
subvet check cdn.example.com
subvet check cdn.example.com --check-ns --check-mx
```

### services

List all supported services.

```bash
subvet services
```

### fingerprint

Show fingerprint details for a service.

```bash
subvet fingerprint "AWS S3"
subvet fingerprint "GitHub Pages"
```

## Output

### JSON (default)

```json
{
  "version": "0.5.0",
  "timestamp": "2026-02-04T00:00:00.000Z",
  "summary": {
    "total": 1,
    "vulnerable": 1,
    "likely": 0,
    "potential": 0,
    "safe": 0
  },
  "results": [{
    "subdomain": "shop.example.com",
    "status": "vulnerable",
    "service": "Shopify",
    "risk": "critical",
    "evidence": [
      "CNAME points to Shopify: shops.myshopify.com",
      "HTTP body matches: \"Sorry, this shop is currently unavailable\"",
      "Confidence: 10/10"
    ],
    "poc": "Create Shopify store and add custom domain"
  }]
}
```

### Status Levels

| Status | Risk | Description | Exit Code |
|--------|------|-------------|-----------|
| `vulnerable` | critical | Confirmed takeover possible | 2 |
| `likely` | high | High probability (NXDOMAIN + known service) | 1 |
| `potential` | medium | Needs manual verification | 0 |
| `not_vulnerable` | info | Properly configured | 0 |

## DNS Security Checks

### NS Delegation (`--check-ns`)

Dangling NS records are **critical** - attackers can register the nameserver domain and gain full DNS control.

```bash
subvet scan example.com --check-ns
```

### MX Records (`--check-mx`)

Dangling MX records allow email interception.

### SPF Includes (`--check-spf`)

Dangling SPF includes enable email spoofing.

### SRV Records (`--check-srv`)

Dangling SRV records can hijack services (autodiscover, SIP, etc.).

## Supported Services

<details>
<summary>Click to expand (80+ services)</summary>

**Cloud Platforms:**
- AWS S3, Elastic Beanstalk, CloudFront, Amplify
- Azure (Web Apps, Blob, CDN, Traffic Manager)
- Google Cloud Storage, Cloud Run
- DigitalOcean App Platform

**Hosting & CDN:**
- GitHub Pages, GitLab Pages
- Heroku, Vercel, Netlify
- Cloudflare Pages, Fastly
- Fly.io, Render, Railway

**Website Builders:**
- Webflow, Wix, Squarespace
- Framer, Carrd, Bubble
- Ghost, Tumblr, WordPress.com

**E-commerce:**
- Shopify, BigCommerce

**Support & Helpdesk:**
- Zendesk, Freshdesk, Intercom
- Help Scout, Canny, UserVoice

**Developer Tools:**
- Bitbucket, Statuspage
- Readme.io, Gitbook, Hashnode

...and many more!

</details>

## Programmatic Usage

```typescript
import { Scanner, quickScan, listServices } from 'subvet';

// Quick scan
const results = await quickScan(['sub.example.com']);

// Custom options
const scanner = new Scanner({
  concurrency: 20,
  timeout: 5000,
  nsCheck: true,
  mxCheck: true
});

const output = await scanner.scan(subdomains);

// Check single
const result = await scanner.scanOne('cdn.example.com');
if (result.status === 'vulnerable') {
  console.log(`Takeover possible via ${result.service}`);
}
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Check for subdomain takeovers
  run: |
    npx subvet scan -f subdomains.txt --check-ns
    if [ $? -eq 2 ]; then
      echo "::error::Vulnerable subdomains found!"
      exit 1
    fi
```

## Project Structure

```
src/
├── cli.ts              # CLI interface
├── scanner.ts          # Main scanning logic
├── dns.ts              # DNS resolution
├── http.ts             # HTTP probing
├── report.ts           # Report generation
├── utils.ts            # Utility functions
├── types.ts            # TypeScript definitions
└── fingerprints/
    ├── index.ts        # Combined exports
    ├── cloud.ts        # AWS, Azure, GCP
    ├── hosting.ts      # GitHub Pages, Vercel...
    ├── website-builders.ts
    ├── ecommerce.ts
    ├── support.ts
    ├── marketing.ts
    ├── devtools.ts
    └── misc.ts
```

## Contributing

Fingerprints are based on [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

To add a new service:

1. Find the appropriate category in `src/fingerprints/`
2. Add fingerprint with:
   - `cnames`: CNAME patterns (glob: `*.example.com`)
   - `fingerprints`: Detection rules with `weight` and `required`
   - `negativePatterns`: Patterns indicating NOT vulnerable
   - `takeoverPossible`: Boolean
   - `poc`: Exploitation steps
3. Run tests: `npm test`
4. Submit PR

## License

MIT

## Related Projects

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Fingerprint reference
- [subjack](https://github.com/haccer/subjack) - Go-based scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) - General vulnerability scanner
