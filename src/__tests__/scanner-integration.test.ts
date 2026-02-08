/**
 * Scanner Integration Tests - Requires real network
 * Run separately: npx vitest run src/__tests__/scanner-integration.test.ts
 */

import { describe, it, expect, vi } from 'vitest';
import { Scanner, quickScan } from '../scanner.js';

describe.skip('Scanner integration (network required)', () => {
  describe('scanOne', () => {
    it('should scan a valid domain', async () => {
      const scanner = new Scanner({ timeout: 10000, httpProbe: true });
      const result = await scanner.scanOne('google.com');
      
      expect(result.subdomain).toBe('google.com');
      expect(result.status).toBe('not_vulnerable');
      expect(result.dns.resolved).toBe(true);
    });

    it('should detect NXDOMAIN', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('nonexistent-domain-xyz-12345.com');
      
      expect(result.dns.nxdomain).toBe(true);
    });

    it('should include timestamp', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('google.com');
      
      expect(result.timestamp).toBeDefined();
      expect(new Date(result.timestamp).getTime()).toBeGreaterThan(0);
    });

    it('should include DNS records', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('google.com');
      
      expect(result.dns).toBeDefined();
      expect(result.dns.subdomain).toBe('google.com');
    });

    it('should handle httpProbe disabled', async () => {
      const scanner = new Scanner({ timeout: 10000, httpProbe: false });
      const result = await scanner.scanOne('google.com');
      
      expect(result.http).toBeUndefined();
    });

    it('should set risk level correctly', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('google.com');
      
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(result.risk);
    });
  });

  describe('scan (batch)', () => {
    it('should scan multiple domains', async () => {
      const scanner = new Scanner({ timeout: 10000, concurrency: 2 });
      const output = await scanner.scan(['google.com', 'github.com']);
      
      expect(output.results.length).toBe(2);
      expect(output.summary.total).toBe(2);
    });

    it('should include version and timestamp', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['google.com']);
      
      expect(output.version).toBeDefined();
      expect(output.timestamp).toBeDefined();
    });

    it('should calculate summary correctly', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const output = await scanner.scan(['google.com']);
      
      expect(output.summary.total).toBe(1);
      expect(output.summary.safe).toBe(1);
      expect(output.summary.vulnerable).toBe(0);
    });
  });

  describe('with NS check', () => {
    it('should check NS records when enabled', async () => {
      const scanner = new Scanner({ timeout: 10000, nsCheck: true });
      const result = await scanner.scanOne('google.com');
      
      expect(result.dns.nsRecords).toBeDefined();
      expect(result.dns.nsRecords!.length).toBeGreaterThan(0);
    });
  });

  describe('with MX check', () => {
    it('should check MX records when enabled', async () => {
      const scanner = new Scanner({ timeout: 10000, mxCheck: true });
      const result = await scanner.scanOne('google.com');
      
      expect(result.dns.mxRecords).toBeDefined();
      expect(result.dns.mxRecords!.length).toBeGreaterThan(0);
    });
  });

  describe('with SPF check', () => {
    it('should check SPF records when enabled', async () => {
      const scanner = new Scanner({ timeout: 10000, spfCheck: true });
      const result = await scanner.scanOne('google.com');
      
      expect(result.dns.spfRecord).toBeDefined();
      expect(result.dns.spfRecord).toContain('v=spf1');
    });
  });

  describe('with SRV check', () => {
    it('should check SRV records when enabled', async () => {
      const scanner = new Scanner({ timeout: 10000, srvCheck: true });
      const result = await scanner.scanOne('google.com');
      
      expect(result.dns.srvRecords).toBeDefined();
    });
  });

  describe('verbose mode', () => {
    it('should work with verbose enabled', async () => {
      const scanner = new Scanner({ timeout: 10000, verbose: true });
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      const output = await scanner.scan(['google.com', 'github.com']);
      expect(output.results.length).toBe(2);
      stderrSpy.mockRestore();
    });
  });

  describe('status classification', () => {
    it('should classify non-vulnerable domains as not_vulnerable', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('google.com');
      expect(result.status).toBe('not_vulnerable');
      expect(result.risk).toBe('info');
    });

    it('should handle domains with CNAME', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('www.github.com');
      expect(result.subdomain).toBe('www.github.com');
    });
  });

  describe('evidence collection', () => {
    it('should collect evidence for resolved domains', async () => {
      const scanner = new Scanner({ timeout: 10000 });
      const result = await scanner.scanOne('google.com');
      expect(Array.isArray(result.evidence)).toBe(true);
    });
  });

  describe('quickScan', () => {
    it('should scan domains quickly', async () => {
      const output = await quickScan(['google.com'], { timeout: 10000 });
      expect(output.results.length).toBe(1);
      expect(output.results[0].status).toBe('not_vulnerable');
    });

    it('should scan multiple domains', async () => {
      const output = await quickScan(['google.com', 'github.com'], { timeout: 10000 });
      expect(output.results.length).toBe(2);
    });
  });
});
