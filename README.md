# SubVet 🔍

**Subdomain Takeover Vulnerability Scanner**

SubVet scans subdomains for potential takeover vulnerabilities by checking DNS records and HTTP responses against a database of 40+ service fingerprints.

## Features

- 🎯 **80+ Service Fingerprints** - AWS S3/CloudFront/Amplify, Azure, Cloudflare Pages, GitHub Pages, Heroku, Shopify, and more
- ⚡ **Fast Concurrent Scanning** - Configurable parallelism
- 📊 **JSON Output** - Easy integration with other tools
- 🔍 **DNS + HTTP Probing** - Comprehensive detection
- 🛡️ **CNAME Chain Following** - Detect dangling records
- 🔐 **NS Delegation Check** - Detect dangling nameservers (critical risk)

## Installation

```bash
npm install -g subvet
```

## Usage

### Quick Check

```bash
# Check a single subdomain
subvet check shop.example.com

# Scan multiple subdomains
subvet scan -f subdomains.txt

# Pipe from other tools
subfinder -d example.com | subvet scan --stdin
```

### Commands

```bash
# Scan with JSON output
subvet scan example.com

# Scan from file
subvet scan -f targets.txt --concurrency 20

# Human-readable single check
subvet check cdn.example.com

# List supported services
subvet services

# Show fingerprint for a service
subvet fingerprint "GitHub Pages"
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-f, --file <path>` | Read subdomains from file | - |
| `--stdin` | Read from stdin | false |
| `-t, --timeout <ms>` | Request timeout | 10000 |
| `-c, --concurrency <n>` | Parallel requests | 10 |
| `--no-http` | Skip HTTP probing | false |
| `--check-ns` | Check for dangling NS delegation | false |
| `--check-mx` | Check for dangling MX records | false |
| `--check-spf` | Check for dangling SPF includes | false |
| `--check-srv` | Check for dangling SRV records | false |
| `-v, --verbose` | Show progress | false |
| `--pretty` | Pretty print JSON | false |
| `--summary` | Show summary only | false |

## Output Format

```json
{
  "version": "0.1.0",
  "timestamp": "2024-01-15T12:00:00.000Z",
  "target": "shop.example.com",
  "summary": {
    "total": 1,
    "vulnerable": 1,
    "likely": 0,
    "potential": 0,
    "safe": 0,
    "errors": 0
  },
  "results": [
    {
      "subdomain": "shop.example.com",
      "status": "vulnerable",
      "service": "Shopify",
      "cname": "shops.myshopify.com",
      "evidence": [
        "CNAME points to Shopify: shops.myshopify.com",
        "HTTP body matches: \"Sorry, this shop is currently unavailable\""
      ],
      "risk": "critical",
      "poc": "Create Shopify store and add custom domain"
    }
  ]
}
```

## Status Levels

| Status | Description | Exit Code |
|--------|-------------|-----------|
| `vulnerable` | Confirmed takeover possible | 2 |
| `likely` | High probability (NXDOMAIN + known service) | 1 |
| `potential` | Needs manual verification | 0 |
| `not_vulnerable` | Properly configured | 0 |

## NS Delegation Check

Dangling NS records are **critical** vulnerabilities. When a subdomain delegates DNS to a nameserver that no longer exists, an attacker can register that nameserver domain and gain full control.

```bash
# Check for dangling NS delegation
subvet scan example.com --check-ns

# Example output for vulnerable subdomain
{
  "status": "vulnerable",
  "service": "NS Delegation",
  "evidence": ["Dangling NS delegation: ns1.defunct-provider.com"],
  "risk": "critical",
  "poc": "Register the dangling nameserver domain and configure DNS zone"
}
```

**Why it's critical:**
- Attacker gains full DNS control over the subdomain
- Can create any record (A, MX, TXT, etc.)
- Enables email interception, phishing, and more
- Often overlooked in traditional CNAME scanning

## Supported Services

<details>
<summary>Click to expand (80+ services)</summary>

**Cloud Platforms:**
- AWS S3, Elastic Beanstalk, CloudFront
- Azure (Web Apps, Blob, CDN, etc.)
- Google Cloud Storage
- Cloudflare Pages

**Hosting:**
- GitHub Pages, GitLab Pages
- Heroku, Vercel, Netlify
- Surge.sh, Fly.io, Render, Railway

**E-commerce:**
- Shopify, BigCommerce

**Marketing & CMS:**
- Webflow, Ghost, Tumblr, WordPress.com
- Unbounce, HubSpot, Wix

**Support:**
- Zendesk, Freshdesk, Intercom

...and more!

</details>

## Programmatic Usage

```typescript
import { Scanner, quickScan, listServices } from 'subvet';

// Quick scan
const results = await quickScan(['sub.example.com']);
console.log(results.summary);

// Custom options
const scanner = new Scanner({
  concurrency: 20,
  timeout: 5000,
  httpProbe: true
});

const output = await scanner.scan(subdomains);

// Check single
const result = await scanner.scanOne('cdn.example.com');
if (result.status === 'vulnerable') {
  console.log(`Takeover possible via ${result.service}`);
}
```

## Integration Examples

### With subfinder

```bash
subfinder -d example.com -silent | subvet scan --stdin -o results.json
```

### With jq

```bash
subvet scan -f subs.txt | jq '.results[] | select(.status == "vulnerable")'
```

### In CI/CD

```yaml
- name: Check for subdomain takeovers
  run: |
    subvet scan -f subdomains.txt
    if [ $? -eq 2 ]; then
      echo "Critical: Vulnerable subdomains found!"
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
├── types.ts            # TypeScript definitions
├── utils.ts            # Utility functions
├── report.ts           # Report generation (JSON/HTML/MD)
├── fingerprints/
│   ├── index.ts        # Combined exports
│   ├── cloud.ts        # AWS, Azure, GCP
│   ├── hosting.ts      # GitHub Pages, Vercel, Netlify...
│   ├── website-builders.ts  # Webflow, Wix, Framer...
│   ├── ecommerce.ts    # Shopify, BigCommerce
│   ├── support.ts      # Zendesk, Freshdesk, Intercom...
│   ├── marketing.ts    # HubSpot, Campaign Monitor...
│   ├── devtools.ts     # Bitbucket, Statuspage, Ngrok...
│   └── misc.ts         # Regional & niche services
└── __tests__/          # Test files
```

## Contributing

Fingerprints are based on [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

To add a new service:

1. Find the appropriate category in `src/fingerprints/`
2. Add your fingerprint with:
   - `cnames`: CNAME patterns (glob-like)
   - `fingerprints`: Detection rules with `weight` and `required`
   - `negativePatterns`: Patterns indicating NOT vulnerable
   - `takeoverPossible`: Boolean
   - `poc`: How to exploit
3. Run tests: `npm test`
4. Submit a PR

## License

MIT

## Related Projects

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Fingerprint reference
- [subjack](https://github.com/haccer/subjack) - Go-based scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) - General vulnerability scanner
