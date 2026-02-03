# SubVet 🔍

**Subdomain Takeover Vulnerability Scanner**

SubVet scans subdomains for potential takeover vulnerabilities by checking DNS records and HTTP responses against a database of 40+ service fingerprints.

## Features

- 🎯 **40+ Service Fingerprints** - AWS S3, Azure, GitHub Pages, Heroku, Shopify, and more
- ⚡ **Fast Concurrent Scanning** - Configurable parallelism
- 📊 **JSON Output** - Easy integration with other tools
- 🔍 **DNS + HTTP Probing** - Comprehensive detection
- 🛡️ **CNAME Chain Following** - Detect dangling records

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
| `-v, --verbose` | Show progress | false |
| `--pretty` | Pretty print JSON | false |

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

## Supported Services

<details>
<summary>Click to expand (40+ services)</summary>

**Cloud Platforms:**
- AWS S3, Elastic Beanstalk
- Azure (Web Apps, Blob, CDN, etc.)
- Google Cloud Storage

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

## Contributing

Fingerprints are based on [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz).

To add a new service:

1. Add fingerprint to `src/fingerprints/index.ts`
2. Include CNAME patterns, HTTP fingerprints, and takeover possibility
3. Submit a PR

## License

MIT

## Related Projects

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) - Fingerprint reference
- [subjack](https://github.com/haccer/subjack) - Go-based scanner
- [nuclei](https://github.com/projectdiscovery/nuclei) - General vulnerability scanner
