/**
 * Slack Module Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatScanMessage, formatDiffMessage, sendSlackWebhook } from '../slack.js';
import type { ScanOutput, ScanResult, DnsResult } from '../types.js';
import type { DiffResult } from '../diff.js';

// Helper to create minimal DNS result
function createDnsResult(subdomain: string): DnsResult {
  return {
    subdomain,
    records: [],
    hasIpv4: true,
    hasIpv6: false,
    resolved: true,
    nxdomain: false,
  };
}

// Helper to create scan result
function createScanResult(
  subdomain: string,
  status: ScanResult['status'],
  service: string | null = null
): ScanResult {
  return {
    subdomain,
    status,
    service,
    cname: null,
    evidence: status === 'vulnerable' ? ['Takeover confirmed'] : [],
    risk: status === 'vulnerable' ? 'critical' : status === 'likely' ? 'high' : 'medium',
    dns: createDnsResult(subdomain),
    timestamp: new Date().toISOString(),
  };
}

// Helper to create scan output
function createScanOutput(results: ScanResult[]): ScanOutput {
  const vulnerable = results.filter(r => r.status === 'vulnerable').length;
  const likely = results.filter(r => r.status === 'likely').length;
  const potential = results.filter(r => r.status === 'potential').length;
  const safe = results.filter(r => r.status === 'not_vulnerable').length;
  const errors = results.filter(r => r.status === 'unknown').length;

  return {
    version: '0.7.0',
    timestamp: '2026-02-04T12:00:00.000Z',
    target: 'example.com',
    options: {
      timeout: 10000,
      concurrency: 10,
      httpProbe: true,
      nsCheck: false,
      mxCheck: false,
      spfCheck: false,
      srvCheck: false,
      verbose: false,
    },
    summary: {
      total: results.length,
      vulnerable,
      likely,
      potential,
      safe,
      errors,
    },
    results,
  };
}

describe('formatScanMessage', () => {
  it('should format clean scan result', () => {
    const output = createScanOutput([
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);

    const message = formatScanMessage(output);

    expect(message.text).toContain('All Clear');
    expect(message.blocks).toBeDefined();
    expect(message.blocks!.length).toBeGreaterThan(0);
  });

  it('should format scan with vulnerabilities', () => {
    const output = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);

    const message = formatScanMessage(output);

    expect(message.text).toContain('🚨');
    expect(message.text).toContain('VULNERABILITIES FOUND');
    
    // Check blocks contain vulnerability info
    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('vuln.example.com');
    expect(blocksStr).toContain('AWS S3');
  });

  it('should format scan with likely issues', () => {
    const output = createScanOutput([
      createScanResult('likely.example.com', 'likely', 'Heroku'),
    ]);

    const message = formatScanMessage(output);

    expect(message.text).toContain('⚠️');
    expect(message.text).toContain('Likely Issues');
  });

  it('should limit findings to 10 items', () => {
    const results = Array.from({ length: 15 }, (_, i) => 
      createScanResult(`vuln${i}.example.com`, 'vulnerable', 'AWS S3')
    );
    const output = createScanOutput(results);

    const message = formatScanMessage(output);
    const blocksStr = JSON.stringify(message.blocks);

    expect(blocksStr).toContain('vuln0.example.com');
    expect(blocksStr).toContain('vuln9.example.com');
    expect(blocksStr).toContain('and 5 more');
  });

  it('should include version and exit code in footer', () => {
    const output = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ]);

    const message = formatScanMessage(output);
    const blocksStr = JSON.stringify(message.blocks);

    expect(blocksStr).toContain('v0.7.0');
    expect(blocksStr).toContain('Exit code: 2');
  });
});

describe('formatDiffMessage', () => {
  it('should format diff with no changes', () => {
    const diff: DiffResult = {
      version: '0.7.0',
      timestamp: '2026-02-04T12:00:00Z',
      baseline: { timestamp: '2026-02-03T12:00:00Z', total: 10 },
      current: { timestamp: '2026-02-04T12:00:00Z', total: 10 },
      summary: {
        newVulnerable: 0,
        newLikely: 0,
        newPotential: 0,
        resolved: 0,
        unchanged: 10,
        statusChanged: 0,
      },
      entries: [],
    };

    const message = formatDiffMessage(diff);

    expect(message.text).toContain('📊');
    expect(message.text).toContain('No Changes');
  });

  it('should format diff with new vulnerabilities', () => {
    const diff: DiffResult = {
      version: '0.7.0',
      timestamp: '2026-02-04T12:00:00Z',
      baseline: { timestamp: '2026-02-03T12:00:00Z', total: 10 },
      current: { timestamp: '2026-02-04T12:00:00Z', total: 11 },
      summary: {
        newVulnerable: 1,
        newLikely: 0,
        newPotential: 0,
        resolved: 0,
        unchanged: 10,
        statusChanged: 0,
      },
      entries: [
        {
          subdomain: 'new-vuln.example.com',
          type: 'new',
          currentStatus: 'vulnerable',
          service: 'GitHub Pages',
          evidence: ['NXDOMAIN'],
          risk: 'critical',
        },
      ],
    };

    const message = formatDiffMessage(diff);

    expect(message.text).toContain('🚨');
    expect(message.text).toContain('NEW VULNERABILITIES');
    
    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('new-vuln.example.com');
    expect(blocksStr).toContain('GitHub Pages');
  });

  it('should format diff with resolved issues', () => {
    const diff: DiffResult = {
      version: '0.7.0',
      timestamp: '2026-02-04T12:00:00Z',
      baseline: { timestamp: '2026-02-03T12:00:00Z', total: 10 },
      current: { timestamp: '2026-02-04T12:00:00Z', total: 10 },
      summary: {
        newVulnerable: 0,
        newLikely: 0,
        newPotential: 0,
        resolved: 1,
        unchanged: 9,
        statusChanged: 0,
      },
      entries: [
        {
          subdomain: 'fixed.example.com',
          type: 'resolved',
          previousStatus: 'vulnerable',
          service: 'AWS S3',
        },
      ],
    };

    const message = formatDiffMessage(diff);

    expect(message.text).toContain('✅');
    expect(message.text).toContain('Issues Resolved');
    
    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('fixed.example.com');
    expect(blocksStr).toContain('was vulnerable');
  });

  it('should include newPotential in diff message', () => {
    const diff: DiffResult = {
      version: '0.8.0',
      timestamp: '2024-01-01T00:00:00Z',
      baseline: { timestamp: '2024-01-01T00:00:00Z', total: 5 },
      current: { timestamp: '2024-01-02T00:00:00Z', total: 6 },
      summary: {
        newVulnerable: 0,
        newLikely: 0,
        newPotential: 1,
        resolved: 0,
        unchanged: 5,
        statusChanged: 0,
      },
      entries: [
        {
          subdomain: 'maybe.example.com',
          type: 'new',
          currentStatus: 'potential',
          service: 'Unknown SaaS',
          evidence: ['Stale CNAME detected'],
          risk: 'medium',
        },
      ],
    };

    const message = formatDiffMessage(diff);

    expect(message.text).toContain('🟡');
    expect(message.text).toContain('New Potential Issues');

    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('New Potential');
    expect(blocksStr).toContain('maybe.example.com');
  });
});

describe('slack-on notification semantics', () => {
  // These test the shouldNotify logic that lives in cli.ts
  // We test the building blocks here: message formatting for diff vs scan

  it('should format diff message with new issues for "new" condition', () => {
    const diff: DiffResult = {
      version: '0.8.0',
      timestamp: '2026-02-08T00:00:00Z',
      baseline: { timestamp: '2026-02-07T00:00:00Z', total: 5 },
      current: { timestamp: '2026-02-08T00:00:00Z', total: 6 },
      summary: {
        newVulnerable: 1,
        newLikely: 0,
        newPotential: 0,
        resolved: 0,
        unchanged: 5,
        statusChanged: 0,
      },
      entries: [{
        subdomain: 'new.example.com',
        type: 'new',
        currentStatus: 'vulnerable',
        service: 'AWS S3',
        evidence: ['NoSuchBucket'],
        risk: 'critical',
      }],
    };

    const message = formatDiffMessage(diff);
    expect(message.text).toContain('NEW VULNERABILITIES');
  });

  it('should format scan message the same way for "new" and "issues" in non-diff mode', () => {
    // In non-diff mode, "new" falls back to "issues" behavior.
    // The message format itself doesn't change; the shouldNotify logic in CLI handles it.
    const output = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ]);
    const message = formatScanMessage(output);
    expect(message.text).toContain('VULNERABILITIES FOUND');
  });
});

describe('sendSlackWebhook', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('should send message to webhook', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => 'ok',
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await sendSlackWebhook('https://hooks.slack.com/test', {
      text: 'Test message',
    });

    expect(result.ok).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://hooks.slack.com/test',
      expect.objectContaining({
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
    );
  });

  it('should handle HTTP errors', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      text: async () => 'not found',
    });
    vi.stubGlobal('fetch', mockFetch);

    const result = await sendSlackWebhook('https://hooks.slack.com/invalid', {
      text: 'Test message',
    });

    expect(result.ok).toBe(false);
    expect(result.error).toContain('404');
  });

  it('should handle network errors', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
    vi.stubGlobal('fetch', mockFetch);

    const result = await sendSlackWebhook('https://hooks.slack.com/test', {
      text: 'Test message',
    });

    expect(result.ok).toBe(false);
    expect(result.error).toContain('Network error');
  });

  it('should timeout after 10 seconds', async () => {
    const abortError = new Error('The operation was aborted');
    abortError.name = 'AbortError';
    const mockFetch = vi.fn().mockRejectedValue(abortError);
    vi.stubGlobal('fetch', mockFetch);

    const result = await sendSlackWebhook('https://hooks.slack.com/test', {
      text: 'Test message',
    });

    expect(result.ok).toBe(false);
    expect(result.error).toBe('Slack webhook timeout');
  });
});

describe('formatScanMessage - potential issues', () => {
  it('should not show All Clear when only potential issues exist', () => {
    const output = createScanOutput([
      createScanResult('pot.example.com', 'potential', 'Unknown SaaS'),
    ]);

    const message = formatScanMessage(output);

    expect(message.text).not.toContain('All Clear');
    expect(message.text).toContain('🟡');
    expect(message.text).toContain('Potential Issues Found');

    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('pot.example.com');
  });

  it('should include potential findings in the findings section', () => {
    const output = createScanOutput([
      createScanResult('pot.example.com', 'potential', 'Stale CNAME'),
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);

    const message = formatScanMessage(output);
    const blocksStr = JSON.stringify(message.blocks);
    expect(blocksStr).toContain('pot.example.com');
    expect(blocksStr).toContain('🟡');
  });
});
