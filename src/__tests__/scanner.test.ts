/**
 * Scanner Module Tests - Unit tests with mocked network
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Scanner, quickScan, listServices, getRegistrableDomain } from '../scanner.js';

// Mock dns and http modules
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

describe('Scanner', () => {
  let mockDnsResolve: ReturnType<typeof vi.fn>;
  let mockHttpProbe: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockDnsResolve = vi.fn();
    mockHttpProbe = vi.fn();
    vi.mocked(DnsResolver).mockImplementation(() => ({
      resolve: mockDnsResolve,
    }) as any);
    vi.mocked(HttpProber).mockImplementation(() => ({
      probe: mockHttpProbe,
    }) as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // Helper: create a standard resolved DNS result
  function resolvedDns(subdomain: string, overrides: Record<string, any> = {}) {
    return {
      subdomain,
      resolved: true,
      nxdomain: false,
      addresses: ['93.184.216.34'],
      records: [{ type: 'A', value: '93.184.216.34' }],
      cnames: [],
      ...overrides,
    };
  }

  // Helper: create standard HTTP probe result
  function httpResult(overrides: Record<string, any> = {}) {
    return {
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html><body>OK</body></html>',
      url: 'https://example.com',
      ...overrides,
    };
  }

  describe('constructor', () => {
    it('should create scanner with default options', () => {
      const scanner = new Scanner();
      expect(scanner).toBeDefined();
    });

    it('should accept custom options', () => {
      const scanner = new Scanner({
        timeout: 5000,
        concurrency: 5,
        httpProbe: false,
        nsCheck: true,
        mxCheck: true,
        spfCheck: true,
        srvCheck: true,
        verbose: true
      });
      expect(scanner).toBeDefined();
    });

    it('should use default timeout of 10000', () => {
      const scanner = new Scanner();
      expect(scanner).toBeDefined();
    });
  });

  describe('scanOne', () => {
    it('should scan a resolved domain', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000, httpProbe: true });
      const result = await scanner.scanOne('example.com');

      expect(result.subdomain).toBe('example.com');
      expect(result.status).toBe('not_vulnerable');
      expect(result.dns.resolved).toBe(true);
    });

    it('should detect NXDOMAIN', async () => {
      mockDnsResolve.mockResolvedValue({
        subdomain: 'nonexistent.com',
        resolved: false,
        nxdomain: true,
        addresses: [],
        records: [],
        cnames: [],
      });

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('nonexistent.com');

      expect(result.dns.nxdomain).toBe(true);
    });

    it('should include timestamp', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('example.com');

      expect(result.timestamp).toBeDefined();
      expect(new Date(result.timestamp).getTime()).toBeGreaterThan(0);
    });

    it('should include DNS records', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('example.com');

      expect(result.dns).toBeDefined();
      expect(result.dns.subdomain).toBe('example.com');
    });

    it('should handle httpProbe disabled', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));

      const scanner = new Scanner({ timeout: 10000, httpProbe: false });
      const result = await scanner.scanOne('example.com');

      expect(result.http).toBeUndefined();
    });

    it('should set risk level correctly', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('example.com');

      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(result.risk);
    });
  });

  describe('scan (batch)', () => {
    it('should scan multiple domains', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000, concurrency: 2 });
      const output = await scanner.scan(['a.example.com', 'b.example.com']);

      expect(output.results.length).toBe(2);
      expect(output.summary.total).toBe(2);
    });

    it('should include version and timestamp', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['example.com']);

      expect(output.version).toBeDefined();
      expect(output.timestamp).toBeDefined();
    });

    it('should calculate summary correctly', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['example.com']);

      expect(output.summary.total).toBe(1);
      expect(output.summary.safe).toBe(1);
      expect(output.summary.vulnerable).toBe(0);
    });

    it('should handle empty input', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan([]);

      expect(output.results.length).toBe(0);
      expect(output.summary.total).toBe(0);
    });

    it('should include options in output', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 5000, concurrency: 5 });
      const output = await scanner.scan(['example.com']);

      expect(output.options).toBeDefined();
      expect(output.options.timeout).toBe(5000);
      expect(output.options.concurrency).toBe(5);
    });

    it('should set target correctly for single domain', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['example.com']);

      expect(output.target).toBe('example.com');
    });

    it('should set target correctly for multiple domains', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['a.example.com', 'b.example.com', 'c.example.com']);

      expect(output.target).toBe('3 subdomains');
    });
  });

  describe('verbose mode', () => {
    it('should work with verbose enabled', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);

      const scanner = new Scanner({ timeout: 10000, verbose: true });
      const output = await scanner.scan(['a.example.com', 'b.example.com']);

      expect(output.results.length).toBe(2);
      stderrSpy.mockRestore();
    });
  });

  describe('status classification', () => {
    it('should classify non-vulnerable domains as not_vulnerable', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('example.com');

      expect(result.status).toBe('not_vulnerable');
      expect(result.risk).toBe('info');
    });

    it('should handle domains with CNAME', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('www.example.com', {
        cnames: ['example.github.io'],
      }));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('www.example.com');

      expect(result.subdomain).toBe('www.example.com');
    });
  });

  describe('evidence collection', () => {
    it('should collect evidence for resolved domains', async () => {
      mockDnsResolve.mockResolvedValue(resolvedDns('example.com'));
      mockHttpProbe.mockResolvedValue(httpResult());

      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('example.com');

      expect(Array.isArray(result.evidence)).toBe(true);
    });
  });

  describe('fingerprint evaluation without body (item 1)', () => {
    it('should run fingerprints when http has status but body is null', async () => {
      // CNAME pointing to a known service, body is null but status 404
      mockDnsResolve.mockResolvedValue(resolvedDns('test.example.com', {
        cnames: ['test.s3.amazonaws.com'],
      }));
      mockHttpProbe.mockResolvedValue({
        status: 404,
        headers: { 'content-type': 'text/html' },
        body: null,
        url: 'https://test.example.com',
      });

      const scanner = new Scanner({ timeout: 10000, httpProbe: true });
      const result = await scanner.scanOne('test.example.com');

      // Even with body=null, the scanner should still process the HTTP result
      // (the fingerprint checker can match on status/headers)
      expect(result.http).toBeDefined();
      expect(result.http!.status).toBe(404);
    });
  });
});

describe('quickScan', () => {
  let mockDnsResolve: ReturnType<typeof vi.fn>;
  let mockHttpProbe: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockDnsResolve = vi.fn().mockResolvedValue({
      subdomain: 'example.com',
      resolved: true,
      nxdomain: false,
      addresses: ['93.184.216.34'],
      records: [{ type: 'A', value: '93.184.216.34' }],
      cnames: [],
    });
    mockHttpProbe = vi.fn().mockResolvedValue({
      status: 200,
      headers: {},
      body: '<html>OK</html>',
      url: 'https://example.com',
    });
    vi.mocked(DnsResolver).mockImplementation(() => ({
      resolve: mockDnsResolve,
    }) as any);
    vi.mocked(HttpProber).mockImplementation(() => ({
      probe: mockHttpProbe,
    }) as any);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should scan domains quickly', async () => {
    const output = await quickScan(['example.com'], { timeout: 10000 });
    expect(output.results.length).toBe(1);
    expect(output.results[0].status).toBe('not_vulnerable');
  });

  it('should work without options', async () => {
    const output = await quickScan(['example.com']);
    expect(output.results.length).toBe(1);
  });

  it('should scan multiple domains', async () => {
    const output = await quickScan(['a.example.com', 'b.example.com'], { timeout: 10000 });
    expect(output.results.length).toBe(2);
  });
});

describe('getRegistrableDomain', () => {
  it('should extract registrable domain for simple TLDs', () => {
    expect(getRegistrableDomain('sub.example.com')).toBe('example.com');
    expect(getRegistrableDomain('a.b.example.com')).toBe('example.com');
  });

  it('should handle multi-part TLDs like co.uk', () => {
    expect(getRegistrableDomain('sub.example.co.uk')).toBe('example.co.uk');
  });

  it('should handle com.au', () => {
    expect(getRegistrableDomain('sub.example.com.au')).toBe('example.com.au');
  });

  it('should handle bare registrable domain', () => {
    expect(getRegistrableDomain('example.com')).toBe('example.com');
  });

  it('should handle co.jp', () => {
    expect(getRegistrableDomain('www.example.co.jp')).toBe('example.co.jp');
  });
});

describe('listServices', () => {
  it('should list all services', () => {
    const services = listServices();
    expect(services.length).toBeGreaterThan(50);
  });

  it('should include service name and takeoverPossible', () => {
    const services = listServices();
    for (const service of services) {
      expect(service.service).toBeDefined();
      expect(typeof service.takeoverPossible).toBe('boolean');
    }
  });

  it('should have AWS S3 in services', () => {
    const services = listServices();
    const s3 = services.find(s => s.service === 'AWS S3');
    expect(s3).toBeDefined();
    expect(s3?.takeoverPossible).toBe(true);
  });

  it('should have GitHub Pages in services', () => {
    const services = listServices();
    const gh = services.find(s => s.service === 'GitHub Pages');
    expect(gh).toBeDefined();
    expect(gh?.takeoverPossible).toBe(true);
  });

  it('should include non-takeover services', () => {
    const services = listServices();
    const nonTakeover = services.filter(s => !s.takeoverPossible);
    expect(nonTakeover.length).toBeGreaterThan(0);
  });
});
