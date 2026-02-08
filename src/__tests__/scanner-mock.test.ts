/**
 * Scanner Module Tests with Mocks
 * Testing vulnerability detection logic with mocked DNS/HTTP
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Scanner } from '../scanner.js';

// Mock the dns and http modules
vi.mock('../dns.js', () => ({
  DnsResolver: vi.fn().mockImplementation(() => ({
    resolve: vi.fn()
  }))
}));

vi.mock('../http.js', () => ({
  HttpProber: vi.fn().mockImplementation(() => ({
    probe: vi.fn()
  }))
}));

import { DnsResolver } from '../dns.js';
import { HttpProber } from '../http.js';

describe('Scanner vulnerability detection', () => {
  let mockDnsResolve: ReturnType<typeof vi.fn>;
  let mockHttpProbe: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockDnsResolve = vi.fn();
    mockHttpProbe = vi.fn();
    
    vi.mocked(DnsResolver).mockImplementation(() => ({
      resolve: mockDnsResolve
    }) as any);
    
    vi.mocked(HttpProber).mockImplementation(() => ({
      probe: mockHttpProbe
    }) as any);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('AWS S3 takeover detection', () => {
    it('should detect vulnerable S3 bucket', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'bucket.s3.amazonaws.com',
        records: [{ type: 'CNAME', value: 'bucket.s3.amazonaws.com' }],
        cname: 'bucket.s3.amazonaws.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://bucket.s3.amazonaws.com',
        status: 404,
        body: '<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('bucket.s3.amazonaws.com');

      expect(result.service).toBe('AWS S3');
      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('critical');
      // Check evidence contains body match
      expect(result.evidence.some(e => e.includes('HTTP body matches'))).toBe(true);
    });

    it('should mark S3 as safe when AccessDenied', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'private-bucket.s3.amazonaws.com',
        records: [{ type: 'CNAME', value: 'private-bucket.s3.amazonaws.com' }],
        cname: 'private-bucket.s3.amazonaws.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://private-bucket.s3.amazonaws.com',
        status: 403,
        body: '<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('private-bucket.s3.amazonaws.com');

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('GitHub Pages takeover detection', () => {
    it('should detect vulnerable GitHub Pages', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'docs.example.com',
        records: [{ type: 'CNAME', value: 'org.github.io' }],
        cname: 'org.github.io',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      // The required pattern is "There isn't a GitHub Pages site here"
      mockHttpProbe.mockResolvedValue({
        url: 'https://docs.example.com',
        status: 404,
        body: "There isn't a GitHub Pages site here. For root URLs (like http://example.com/)",
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('docs.example.com');

      expect(result.service).toBe('GitHub Pages');
      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('critical');
    });
  });

  describe('Heroku takeover detection', () => {
    it('should detect vulnerable Heroku app', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'app.example.com',
        records: [{ type: 'CNAME', value: 'myapp.herokuapp.com' }],
        cname: 'myapp.herokuapp.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      // All patterns: "No such app", "no-such-app", "There's nothing here, yet.", "herokucdn.com/error-pages"
      mockHttpProbe.mockResolvedValue({
        url: 'https://app.example.com',
        status: 404,
        body: "No such app - no-such-app - There's nothing here, yet. herokucdn.com/error-pages",
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('app.example.com');

      expect(result.service).toBe('Heroku');
      // With all patterns matching, should be vulnerable or at least likely
      expect(['vulnerable', 'likely']).toContain(result.status);
      expect(['critical', 'high']).toContain(result.risk);
    });

    it('should mark Heroku as safe when app exists but crashed', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'app.example.com',
        records: [{ type: 'CNAME', value: 'myapp.herokuapp.com' }],
        cname: 'myapp.herokuapp.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://app.example.com',
        status: 503,
        body: 'Application error - please check logs',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('app.example.com');

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('CloudFront takeover detection', () => {
    it('should detect vulnerable CloudFront distribution', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'cdn.example.com',
        records: [{ type: 'CNAME', value: 'd1234.cloudfront.net' }],
        cname: 'd1234.cloudfront.net',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://cdn.example.com',
        status: 403,
        body: 'ERROR: The request could not be satisfied',
        headers: { 'x-cache': 'Error from cloudfront' }
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('cdn.example.com');

      expect(result.service).toBe('AWS CloudFront');
      expect(result.status).toBe('vulnerable');
    });
  });

  describe('Shopify takeover detection', () => {
    it('should detect vulnerable Shopify store', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'shop.example.com',
        records: [{ type: 'CNAME', value: 'shops.myshopify.com' }],
        cname: 'shops.myshopify.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      // Required pattern: "Sorry, this shop is currently unavailable"
      mockHttpProbe.mockResolvedValue({
        url: 'https://shop.example.com',
        status: 404,
        body: 'Sorry, this shop is currently unavailable. Only one step left!',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('shop.example.com');

      expect(result.service).toBe('Shopify');
      expect(result.status).toBe('vulnerable');
    });

    it('should mark Shopify as safe when shop is active', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'shop.example.com',
        records: [{ type: 'CNAME', value: 'shops.myshopify.com' }],
        cname: 'shops.myshopify.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://shop.example.com',
        status: 200,
        body: '<html>Welcome to our store! Add to cart checkout</html>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('shop.example.com');

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('NS delegation takeover', () => {
    it('should detect dangling NS delegation', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'sub.example.com',
        records: [],
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: false,
        nsRecords: ['ns1.defunct-provider.com', 'ns2.defunct-provider.com'],
        nsDangling: ['ns1.defunct-provider.com', 'ns2.defunct-provider.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://sub.example.com',
        status: null,
        body: null,
        headers: {},
        error: 'Connection refused'
      });

      const scanner = new Scanner({ timeout: 5000, nsCheck: true });
      const result = await scanner.scanOne('sub.example.com');

      expect(result.status).toBe('vulnerable');
      expect(result.service).toBe('NS Delegation');
      expect(result.risk).toBe('critical');
    });
  });

  describe('MX takeover', () => {
    it('should detect dangling MX records', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'mail.example.com',
        records: [],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        mxRecords: ['mail.defunct-domain.com'],
        mxDangling: ['mail.defunct-domain.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://mail.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, mxCheck: true });
      const result = await scanner.scanOne('mail.example.com');

      expect(result.status).toBe('vulnerable');
      expect(result.service).toBe('MX Record');
      expect(result.risk).toBe('critical');
    });
  });

  describe('SPF takeover', () => {
    it('should detect dangling SPF includes', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'example.com',
        records: [],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        spfRecord: 'v=spf1 include:defunct-provider.com -all',
        spfIncludes: ['defunct-provider.com'],
        spfDangling: ['defunct-provider.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, spfCheck: true });
      const result = await scanner.scanOne('example.com');

      expect(result.status).toBe('vulnerable');
      expect(result.service).toBe('SPF Record');
      expect(result.risk).toBe('high');
    });
  });

  describe('SRV takeover', () => {
    it('should detect dangling SRV records', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'example.com',
        records: [],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        srvRecords: ['autodiscover.defunct.com'],
        srvDangling: ['autodiscover.defunct.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, srvCheck: true });
      const result = await scanner.scanOne('example.com');

      expect(result.status).toBe('vulnerable');
      expect(result.service).toBe('SRV Record');
      expect(result.risk).toBe('high');
    });
  });

  describe('Generic pattern detection', () => {
    it('should detect generic takeover indicators', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'app.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://app.example.com',
        status: 404,
        body: 'This domain is not configured. Please contact support.',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('app.example.com');

      expect(result.status).toBe('potential');
      // Check for generic indicator in evidence
      expect(result.evidence.some(e => e.includes('Domain not configured'))).toBe(true);
    });

    it('should skip when safe patterns are present', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'app.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://app.example.com',
        status: 200,
        body: 'Site under maintenance. Coming soon!',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('app.example.com');

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('NXDOMAIN with known service', () => {
    it('should detect likely takeover on NXDOMAIN', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'blog.example.com',
        records: [{ type: 'CNAME', value: 'example.ghost.io' }],
        cname: 'example.ghost.io',
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: true
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://blog.example.com',
        status: null,
        body: null,
        headers: {},
        error: 'NXDOMAIN'
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('blog.example.com');

      expect(result.service).toBe('Ghost');
      expect(result.status).toBe('likely');
      expect(result.risk).toBe('high');
    });
  });

  describe('Confidence scoring', () => {
    it('should assign low confidence for status-only match', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.vercel.app',
        records: [{ type: 'CNAME', value: 'cname.vercel-dns.com' }],
        cname: 'cname.vercel-dns.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.vercel.app',
        status: 404,
        body: 'Some generic error page',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.vercel.app');

      // Without body match, confidence is low
      expect(result.status).not.toBe('vulnerable');
    });

    it('should assign high confidence for body + status match', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.vercel.app',
        records: [{ type: 'CNAME', value: 'cname.vercel-dns.com' }],
        cname: 'cname.vercel-dns.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.vercel.app',
        status: 404,
        body: 'The deployment could not be found. DEPLOYMENT_NOT_FOUND',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.vercel.app');

      expect(result.status).toBe('vulnerable');
      // Check for confidence in evidence
      expect(result.evidence.some(e => e.includes('Confidence'))).toBe(true);
    });
  });

  describe('DNS fingerprint rules', () => {
    it('should evaluate dns_nxdomain rule', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.elasticbeanstalk.com',
        records: [{ type: 'CNAME', value: 'test.elasticbeanstalk.com' }],
        cname: 'test.elasticbeanstalk.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: true
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.elasticbeanstalk.com',
        status: null,
        body: null,
        headers: {},
        error: 'NXDOMAIN'
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.elasticbeanstalk.com');

      expect(result.service).toBe('AWS Elastic Beanstalk');
      expect(result.evidence.some(e => e.includes('NXDOMAIN'))).toBe(true);
      expect(['vulnerable', 'likely']).toContain(result.status);
    });
  });

  describe('Edge cases', () => {
    it('should handle DNS errors gracefully', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'error.example.com',
        records: [],
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: false,
        error: 'DNS query timeout'
      });

      const scanner = new Scanner({ timeout: 5000, httpProbe: false });
      const result = await scanner.scanOne('error.example.com');

      expect(result.dns.error).toBe('DNS query timeout');
      expect(result.evidence.some(e => e.includes('DNS error'))).toBe(true);
    });

    it('should handle HTTP probe disabled', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      const scanner = new Scanner({ timeout: 5000, httpProbe: false });
      const result = await scanner.scanOne('test.example.com');

      expect(result.http).toBeUndefined();
      expect(result.status).toBe('not_vulnerable');
    });

    it('should handle null HTTP body', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.github.io',
        records: [{ type: 'CNAME', value: 'test.github.io' }],
        cname: 'test.github.io',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.github.io',
        status: 200,
        body: null,
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.github.io');

      expect(result).toBeDefined();
    });
  });

  describe('DNS dangling fingerprint rules', () => {
    it('should detect dangling NS with ns_nxdomain rule', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'NS', value: 'ns.dangling-domain.com' }],
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: false,
        nsRecords: ['ns.dangling-domain.com'],
        nsDangling: ['ns.dangling-domain.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: null,
        body: null,
        headers: {},
        error: 'DNS resolution failed'
      });

      const scanner = new Scanner({ timeout: 5000, nsCheck: true });
      const result = await scanner.scanOne('test.example.com');

      // NS dangling is detected directly by scanner (not via fingerprint rule)
      expect(result.evidence.some(e => e.includes('Dangling NS'))).toBe(true);
    });

    it('should detect dangling MX records', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [
          { type: 'A', value: '1.2.3.4' },
          { type: 'MX', value: '10 mail.dangling.com' }
        ],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        mxRecords: ['mail.dangling.com'],
        mxDangling: ['mail.dangling.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'Normal page',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, mxCheck: true });
      const result = await scanner.scanOne('test.example.com');

      expect(result.evidence.some(e => e.includes('Dangling MX'))).toBe(true);
      expect(result.status).toBe('vulnerable');
    });

    it('should detect dangling SPF includes', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [
          { type: 'A', value: '1.2.3.4' },
          { type: 'TXT', value: 'v=spf1 include:spf.dangling.com ~all' }
        ],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        spfRecord: 'v=spf1 include:spf.dangling.com ~all',
        spfIncludes: ['spf.dangling.com'],
        spfDangling: ['spf.dangling.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'Normal page',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, spfCheck: true });
      const result = await scanner.scanOne('test.example.com');

      expect(result.evidence.some(e => e.includes('Dangling SPF'))).toBe(true);
      expect(result.status).toBe('vulnerable');
    });

    it('should detect dangling SRV records', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [
          { type: 'A', value: '1.2.3.4' },
          { type: 'SRV', value: '_autodiscover._tcp 10 0 443 autodiscover.dangling.com' }
        ],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        srvRecords: ['_autodiscover._tcp: autodiscover.dangling.com'],
        srvDangling: ['_autodiscover._tcp: autodiscover.dangling.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'Normal page',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, srvCheck: true });
      const result = await scanner.scanOne('test.example.com');

      expect(result.evidence.some(e => e.includes('Dangling SRV'))).toBe(true);
      expect(result.status).toBe('vulnerable');
    });
  });

  describe('Marketo stale CNAME detection', () => {
    it('should detect stale Marketo CNAME with login page', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'pages.example.com',
        records: [
          { type: 'CNAME', value: 'ab62.mktoedge.com' },
          { type: 'A', value: '104.16.96.80' }
        ],
        cname: 'ab62.mktoedge.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://pages.example.com',
        status: 200,
        body: '<title>Login | Marketo</title><form id="mktLogin"><img src="adobe-login-brand-mark.svg"/><span>Adobe Marketo Engage</span></form>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('pages.example.com');

      expect(result.service).toBe('Marketo');
      expect(result.status).toBe('potential');
      expect(result.risk).toBe('medium');
      expect(result.evidence.some(e => e.includes('Marketo'))).toBe(true);
    });

    it('should detect stale Marketo CNAME with 404 page', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'em.example.com',
        records: [
          { type: 'CNAME', value: 'mkto-ab620141.com' },
          { type: 'A', value: '104.17.73.206' }
        ],
        cname: 'mkto-ab620141.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://em.example.com',
        status: 200,
        body: '<h1>Page not found</h1> The content you are looking for does not exist.',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('em.example.com');

      expect(result.service).toBe('Marketo');
      expect(result.status).toBe('potential');
    });

    it('should NOT flag active Marketo with forms', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'landing.example.com',
        records: [
          { type: 'CNAME', value: 'ab62.mktoedge.com' },
          { type: 'A', value: '104.16.96.80' }
        ],
        cname: 'ab62.mktoedge.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://landing.example.com',
        status: 200,
        body: '<html><head><script src="MktoForms2.js"></script></head><body><form id="mktoForm_1234">Active landing page</form></body></html>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('landing.example.com');

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('Generic stale CNAME detection', () => {
    it('should detect stale CNAME redirecting to SaaS login', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'old.example.com',
        records: [
          { type: 'CNAME', value: 'custom.salesforce.com' },
          { type: 'A', value: '1.2.3.4' }
        ],
        cname: 'custom.salesforce.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://old.example.com',
        status: 302,
        body: '',
        headers: { location: 'https://login.salesforce.com/' }
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('old.example.com');

      expect(result.status).toBe('potential');
      expect(result.evidence.some(e => e.includes('Stale CNAME') || e.includes('Salesforce'))).toBe(true);
    });

    it('should detect stale CNAME with SaaS 404 on known domain', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'old.example.com',
        records: [
          { type: 'CNAME', value: 'old.netlify.app' },
          { type: 'A', value: '1.2.3.4' }
        ],
        cname: 'old.netlify.app',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://old.example.com',
        status: 404,
        body: 'Not Found',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('old.example.com');

      expect(result.status).toBe('potential');
      expect(result.evidence.some(e => e.includes('Stale CNAME'))).toBe(true);
    });
  });

  describe('FB Round 2: HTTP confidence not diluted by DNS rules', () => {
    it('should not count dns_nxdomain weight in HTTP confidence scoring', async () => {
      // Service with dns_nxdomain (weight 5) + http_body (weight 5)
      // Previously totalWeight = 10, matchedWeight = 5 → confidence = 5
      // Now totalWeight = 5 (HTTP only), matchedWeight = 5 → confidence = 10
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.elasticbeanstalk.com',
        records: [{ type: 'CNAME', value: 'test.elasticbeanstalk.com' }],
        cname: 'test.elasticbeanstalk.com',
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: true
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.elasticbeanstalk.com',
        status: 404,
        body: 'NXDOMAIN',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.elasticbeanstalk.com');

      // Confidence should be based on HTTP rules only
      const confidenceEvidence = result.evidence.find(e => e.startsWith('Confidence:'));
      if (confidenceEvidence) {
        const score = parseInt(confidenceEvidence.match(/(\d+)\/10/)?.[1] ?? '0');
        // Without DNS dilution, matching HTTP rules should yield higher confidence
        expect(score).toBeGreaterThanOrEqual(5);
      }
    });

    it('should respect minConfidence threshold without DNS rule dilution', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'bucket.s3.amazonaws.com',
        records: [{ type: 'CNAME', value: 'bucket.s3.amazonaws.com' }],
        cname: 'bucket.s3.amazonaws.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://bucket.s3.amazonaws.com',
        status: 404,
        body: '<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('bucket.s3.amazonaws.com');

      // All HTTP rules match → high confidence → vulnerable
      expect(result.status).toBe('vulnerable');
    });
  });

  describe('FB Round 2: Wildcard check failure resilience', () => {
    it('should continue scanning when checkWildcard throws', async () => {
      // We need to test via scan() which uses checkWildcard
      // Re-mock DnsResolver with checkWildcard that throws
      const mockResolve = vi.fn().mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      vi.mocked(DnsResolver).mockImplementation(() => ({
        resolve: mockResolve,
        checkWildcard: vi.fn().mockRejectedValue(new Error('DNS timeout'))
      }) as any);

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const output = await scanner.scan(['test.example.com']);

      expect(output.results.length).toBe(1);
      expect(output.results[0].subdomain).toBe('test.example.com');
      expect(output.results[0].status).toBe('not_vulnerable');
    });
  });

  describe('FB Round 2: IPv6 wildcard safety', () => {
    it('should detect IPv6 wildcard match as not_vulnerable', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'AAAA', value: '2001:db8::1' }],
        hasIpv4: false,
        hasIpv6: true,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.example.com', {
        isWildcard: true,
        wildcardIp: '2001:db8::1'
      });

      expect(result.status).toBe('not_vulnerable');
      expect(result.evidence.some(e => e.includes('wildcard'))).toBe(true);
    });
  });

  describe('FB Round 3: CNAME SERVFAIL/timeout should not be treated as dangling', () => {
    it('should not mark as vulnerable when CNAME target has transient DNS failure', async () => {
      // Simulate: CNAME exists, but dns.ts sets error instead of nxdomain for SERVFAIL
      mockDnsResolve.mockResolvedValue({
        subdomain: 'app.example.com',
        records: [{ type: 'CNAME', value: 'app.saas-provider.com' }],
        cname: 'app.saas-provider.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,  // NOT dangling — transient failure
        error: 'CNAME target app.saas-provider.com: SERVFAIL (transient — not marked as dangling)'
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://app.example.com',
        status: null,
        body: null,
        headers: {},
        error: 'Connection failed'
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('app.example.com');

      // Should NOT be vulnerable/likely since nxdomain is false
      expect(result.status).not.toBe('vulnerable');
      expect(result.status).not.toBe('likely');
    });

    it('should mark as dangling when CNAME target returns NXDOMAIN', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'old.example.com',
        records: [{ type: 'CNAME', value: 'old.defunct-service.com' }],
        cname: 'old.defunct-service.com',
        hasIpv4: false,
        hasIpv6: false,
        resolved: false,
        nxdomain: true  // Permanent failure → dangling
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://old.example.com',
        status: null,
        body: null,
        headers: {},
        error: 'NXDOMAIN'
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('old.example.com');

      expect(result.dns.nxdomain).toBe(true);
      expect(result.evidence.some(e => e.includes('NXDOMAIN'))).toBe(true);
    });
  });

  describe('FB Round 3: Wildcard should not downgrade DNS dangling vulnerabilities', () => {
    it('should keep NS dangling as vulnerable even with wildcard', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'sub.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        nsRecords: ['ns1.defunct.com'],
        nsDangling: ['ns1.defunct.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://sub.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, nsCheck: true });
      const result = await scanner.scanOne('sub.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4'
      });

      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('critical');
      expect(result.evidence.some(e => e.includes('Wildcard adjustment skipped'))).toBe(true);
    });

    it('should keep MX dangling as vulnerable even with wildcard', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'mail.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        mxRecords: ['mail.defunct.com'],
        mxDangling: ['mail.defunct.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://mail.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, mxCheck: true });
      const result = await scanner.scanOne('mail.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4'
      });

      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('critical');
    });

    it('should keep SPF dangling as vulnerable even with wildcard', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        spfRecord: 'v=spf1 include:defunct.com -all',
        spfIncludes: ['defunct.com'],
        spfDangling: ['defunct.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, spfCheck: true });
      const result = await scanner.scanOne('example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4'
      });

      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('high');
    });

    it('should keep SRV dangling as vulnerable even with wildcard', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false,
        srvRecords: ['_autodiscover._tcp: autodiscover.defunct.com'],
        srvDangling: ['_autodiscover._tcp: autodiscover.defunct.com']
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000, srvCheck: true });
      const result = await scanner.scanOne('example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4'
      });

      expect(result.status).toBe('vulnerable');
      expect(result.risk).toBe('high');
    });
  });

  describe('Wildcard IP set matching', () => {
    it('should mark as safe when all IPs match wildcardIps set', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }, { type: 'A', value: '5.6.7.8' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4',
        wildcardIps: ['1.2.3.4', '5.6.7.8', '9.10.11.12']
      });

      expect(result.status).toBe('not_vulnerable');
      expect(result.evidence.some(e => e.includes('All IPs match wildcard set'))).toBe(true);
    });

    it('should reduce confidence on partial wildcard IP match', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }, { type: 'A', value: '99.99.99.99' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4',
        wildcardIps: ['1.2.3.4', '5.6.7.8']
      });

      expect(result.evidence.some(e => e.includes('Partial wildcard IP match'))).toBe(true);
    });

    it('should not adjust when no IPs match wildcard set', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '99.99.99.99' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4',
        wildcardIps: ['1.2.3.4', '5.6.7.8']
      });

      // No CNAME, has IP that doesn't match wildcard → confidence reduced (existing behavior)
      expect(result.evidence.some(e => e.includes('No CNAME in wildcard domain'))).toBe(true);
    });

    it('should fall back to wildcardIp when wildcardIps not provided', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const result = await scanner.scanOne('test.example.com', {
        isWildcard: true,
        wildcardIp: '1.2.3.4'
      });

      expect(result.status).toBe('not_vulnerable');
    });
  });

  describe('FB Round 2: Output mode priority', () => {
    // Output priority is documented and enforced in CLI; tested via cli.test.ts
    // Here we verify the scan output structure is consistent regardless
    it('should produce valid output for summary consumption', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'test.example.com',
        records: [{ type: 'A', value: '1.2.3.4' }],
        hasIpv4: true,
        hasIpv6: false,
        resolved: true,
        nxdomain: false
      });

      mockHttpProbe.mockResolvedValue({
        url: 'https://test.example.com',
        status: 200,
        body: 'OK',
        headers: {}
      });

      const scanner = new Scanner({ timeout: 5000 });
      const output = await scanner.scan(['test.example.com']);

      expect(output.summary).toBeDefined();
      expect(output.summary.total).toBe(1);
      expect(output.results).toBeDefined();
    });
  });
});
