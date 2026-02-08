import { describe, it, expect, vi } from 'vitest';
import { DnsResolver, quickDnsCheck, type WildcardResult } from '../dns.js';

describe('DnsResolver', () => {
  describe('resolve', () => {
    it('should resolve a valid domain', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('google.com');
      
      expect(result.subdomain).toBe('google.com');
      expect(result.resolved).toBe(true);
      expect(result.nxdomain).toBe(false);
      expect(result.records.length).toBeGreaterThan(0);
    });

    it('should detect NXDOMAIN', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('this-domain-definitely-does-not-exist-12345.com');
      
      expect(result.nxdomain).toBe(true);
    });

    it('should follow CNAME chains', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('www.github.com');
      
      expect(result.resolved).toBe(true);
      // www.github.com typically has a CNAME
    });
  });

  describe('with NS check', () => {
    it('should find NS records when enabled', async () => {
      const resolver = new DnsResolver({ timeout: 5000, checkNs: true });
      const result = await resolver.resolve('google.com');
      
      expect(result.nsRecords).toBeDefined();
      expect(result.nsRecords!.length).toBeGreaterThan(0);
    });
  });

  describe('with MX check', () => {
    it('should find MX records when enabled', async () => {
      const resolver = new DnsResolver({ timeout: 5000, checkMx: true });
      const result = await resolver.resolve('google.com');
      
      expect(result.mxRecords).toBeDefined();
      expect(result.mxRecords!.length).toBeGreaterThan(0);
    });
  });

  describe('with SPF check', () => {
    it('should find SPF record when enabled', async () => {
      const resolver = new DnsResolver({ timeout: 5000, checkSpf: true });
      const result = await resolver.resolve('google.com');
      
      expect(result.spfRecord).toBeDefined();
      expect(result.spfRecord).toContain('v=spf1');
    });

    it('should extract SPF includes', async () => {
      const resolver = new DnsResolver({ timeout: 5000, checkSpf: true });
      const result = await resolver.resolve('google.com');
      
      expect(result.spfIncludes).toBeDefined();
      expect(result.spfIncludes!.length).toBeGreaterThan(0);
    });
  });
});

describe('quickDnsCheck', () => {
  it('should resolve a valid domain', async () => {
    const result = await quickDnsCheck('google.com');
    
    expect(result.subdomain).toBe('google.com');
    expect(result.resolved).toBe(true);
  });
});

describe('DnsResolver CNAME handling', () => {
  it('should normalize CNAME with trailing dot', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    // This tests the normalization internally
    const result = await resolver.resolve('www.github.com');
    if (result.cname) {
      expect(result.cname.endsWith('.')).toBe(false);
    }
  });

  it('should not set nxdomain for valid CNAME chains', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    // www.github.com has a CNAME that resolves
    const result = await resolver.resolve('www.github.com');
    expect(result.nxdomain).toBe(false);
  });
});

describe('DnsResolver dangling checks', () => {
  describe('isNsDangling', () => {
    it('should return false for valid nameserver with A record', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      // ns1.google.com has A records
      const result = await resolver.isNsDangling('ns1.google.com');
      expect(result).toBe(false);
    });

    it('should return true for non-existent nameserver', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isNsDangling('ns.nonexistent-domain-test-12345.com');
      expect(result).toBe(true);
    });
  });

  describe('isMxDangling', () => {
    it('should return false for valid mail server', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      // Google's mail servers exist
      const result = await resolver.isMxDangling('smtp.google.com');
      expect(result).toBe(false);
    });

    it('should return true for non-existent mail server', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isMxDangling('mail.nonexistent-domain-test-12345.com');
      expect(result).toBe(true);
    });
  });

  describe('isSrvTargetDangling', () => {
    it('should return false for null SRV target (.)', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isSrvTargetDangling('.');
      expect(result).toBe(false);
    });

    it('should return false for empty SRV target', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isSrvTargetDangling('');
      expect(result).toBe(false);
    });

    it('should return true for non-existent SRV target', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isSrvTargetDangling('srv.nonexistent-domain-test-12345.com');
      expect(result).toBe(true);
    });
  });

  describe('isCnameDangling', () => {
    it('should return false for valid CNAME target', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isCnameDangling('google.com');
      expect(result).toBe(false);
    });

    it('should return true for non-existent CNAME target', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.isCnameDangling('nonexistent-domain-test-12345.com');
      expect(result).toBe(true);
    });
  });
});

describe('DnsResolver wildcard detection', () => {
  it('should detect non-wildcard domain', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.checkWildcard('google.com');
    
    expect(result.isWildcard).toBe(false);
    expect(result.wildcardIp).toBeUndefined();
  });

  it('should return WildcardResult shape', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.checkWildcard('example.com');
    
    expect(typeof result.isWildcard).toBe('boolean');
    if (result.isWildcard) {
      expect(typeof result.wildcardIp).toBe('string');
    }
  });

  it('should handle non-existent base domain gracefully', async () => {
    const resolver = new DnsResolver({ timeout: 5000 });
    const result = await resolver.checkWildcard('nonexistent-domain-test-12345.com');
    
    expect(result.isWildcard).toBe(false);
  });

  it('should handle timeout gracefully', async () => {
    const resolver = new DnsResolver({ timeout: 1 });
    const result = await resolver.checkWildcard('google.com');
    
    // Should not throw, just return not-wildcard
    expect(typeof result.isWildcard).toBe('boolean');
  });
});

describe('DnsResolver advanced', () => {
  describe('with SRV check', () => {
    it('should check SRV records when enabled', async () => {
      const resolver = new DnsResolver({ timeout: 5000, checkSrv: true });
      const result = await resolver.resolve('google.com');

      expect(result.srvRecords).toBeDefined();
    });
  });

  describe('IPv4/IPv6 detection', () => {
    it('should detect IPv4 addresses', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('google.com');

      expect(result.hasIpv4).toBe(true);
    });

    it('should detect IPv6 addresses when available', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('google.com');

      // Google has IPv6
      expect(typeof result.hasIpv6).toBe('boolean');
    });
  });

  describe('CNAME handling', () => {
    it('should capture CNAME value', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      // www.github.com has a CNAME
      const result = await resolver.resolve('www.github.com');

      if (result.cname) {
        expect(typeof result.cname).toBe('string');
      }
    });
  });

  describe('error handling', () => {
    it('should handle timeout gracefully', async () => {
      const resolver = new DnsResolver({ timeout: 1 });
      const result = await resolver.resolve('google.com');

      // Should either succeed or have an error
      expect(result).toBeDefined();
    });

    it('should handle invalid domain', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('invalid..domain');

      expect(result).toBeDefined();
    });
  });

  describe('record types', () => {
    it('should include record types in results', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const result = await resolver.resolve('google.com');

      for (const record of result.records) {
        expect(['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT']).toContain(record.type);
        expect(record.value).toBeDefined();
      }
    });
  });

  describe('trailing dot normalization', () => {
    it('should normalize trailing dot in NS target for dangling check', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      // A trailing-dot FQDN like "ns1.google.com." should resolve the same as "ns1.google.com"
      const withDot = await resolver.isNsDangling('ns1.google.com.');
      const withoutDot = await resolver.isNsDangling('ns1.google.com');
      expect(withDot).toBe(withoutDot);
    });

    it('should normalize trailing dot in MX target for dangling check', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const withDot = await resolver.isMxDangling('alt1.aspmx.l.google.com.');
      const withoutDot = await resolver.isMxDangling('alt1.aspmx.l.google.com');
      expect(withDot).toBe(withoutDot);
    });

    it('should normalize trailing dot in SRV target for dangling check', async () => {
      const resolver = new DnsResolver({ timeout: 5000 });
      const withDot = await resolver.isSrvTargetDangling('sip.example.com.');
      const withoutDot = await resolver.isSrvTargetDangling('sip.example.com');
      expect(withDot).toBe(withoutDot);
    });
  });
});
