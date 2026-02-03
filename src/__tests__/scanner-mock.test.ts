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
});
