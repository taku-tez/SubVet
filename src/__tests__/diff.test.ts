/**
 * Diff Module Tests
 */

import { describe, it, expect } from 'vitest';
import { compareScans, formatDiffText, getDiffExitCode, type DiffResult } from '../diff.js';
import type { ScanOutput, ScanResult, DnsResult } from '../types.js';

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
    version: '0.6.0',
    timestamp: new Date().toISOString(),
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

describe('compareScans', () => {
  it('should detect no changes when scans are identical', () => {
    const results = [
      createScanResult('safe.example.com', 'not_vulnerable'),
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ];
    const baseline = createScanOutput(results);
    const current = createScanOutput(results);

    const diff = compareScans(baseline, current);

    expect(diff.summary.newVulnerable).toBe(0);
    expect(diff.summary.newLikely).toBe(0);
    expect(diff.summary.newPotential).toBe(0);
    expect(diff.summary.resolved).toBe(0);
    expect(diff.summary.unchanged).toBe(2);
    expect(diff.entries).toHaveLength(0);
  });

  it('should detect new vulnerable subdomain', () => {
    const baseline = createScanOutput([
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);
    const current = createScanOutput([
      createScanResult('safe.example.com', 'not_vulnerable'),
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.newVulnerable).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].subdomain).toBe('vuln.example.com');
    expect(diff.entries[0].type).toBe('new');
    expect(diff.entries[0].currentStatus).toBe('vulnerable');
  });

  it('should detect new likely subdomain', () => {
    const baseline = createScanOutput([]);
    const current = createScanOutput([
      createScanResult('likely.example.com', 'likely', 'Heroku'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.newLikely).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].type).toBe('new');
    expect(diff.entries[0].currentStatus).toBe('likely');
  });

  it('should detect resolved vulnerability', () => {
    const baseline = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ]);
    const current = createScanOutput([
      createScanResult('vuln.example.com', 'not_vulnerable'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.resolved).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].subdomain).toBe('vuln.example.com');
    expect(diff.entries[0].type).toBe('resolved');
    expect(diff.entries[0].previousStatus).toBe('vulnerable');
  });

  it('should detect resolved when subdomain is removed', () => {
    const baseline = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);
    const current = createScanOutput([
      createScanResult('safe.example.com', 'not_vulnerable'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.resolved).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].subdomain).toBe('vuln.example.com');
    expect(diff.entries[0].type).toBe('resolved');
  });

  it('should detect status changes between risky states', () => {
    const baseline = createScanOutput([
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
    ]);
    const current = createScanOutput([
      createScanResult('vuln.example.com', 'likely', 'AWS S3'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.statusChanged).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].type).toBe('changed');
    expect(diff.entries[0].previousStatus).toBe('vulnerable');
    expect(diff.entries[0].currentStatus).toBe('likely');
  });

  it('should treat safe-to-risky as new vulnerability', () => {
    const baseline = createScanOutput([
      createScanResult('was-safe.example.com', 'not_vulnerable'),
    ]);
    const current = createScanOutput([
      createScanResult('was-safe.example.com', 'vulnerable', 'AWS S3'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.summary.newVulnerable).toBe(1);
    expect(diff.entries).toHaveLength(1);
    expect(diff.entries[0].type).toBe('new');
  });

  it('should sort entries by severity (vulnerable > likely > potential)', () => {
    const baseline = createScanOutput([]);
    const current = createScanOutput([
      createScanResult('potential.example.com', 'potential'),
      createScanResult('vuln.example.com', 'vulnerable', 'AWS S3'),
      createScanResult('likely.example.com', 'likely', 'Heroku'),
    ]);

    const diff = compareScans(baseline, current);

    expect(diff.entries).toHaveLength(3);
    expect(diff.entries[0].currentStatus).toBe('vulnerable');
    expect(diff.entries[1].currentStatus).toBe('likely');
    expect(diff.entries[2].currentStatus).toBe('potential');
  });

  it('should handle complex mixed scenario', () => {
    const baseline = createScanOutput([
      createScanResult('unchanged.example.com', 'not_vulnerable'),
      createScanResult('will-resolve.example.com', 'vulnerable', 'AWS S3'),
      createScanResult('will-change.example.com', 'likely', 'Heroku'),
      createScanResult('removed-safe.example.com', 'not_vulnerable'),
    ]);
    const current = createScanOutput([
      createScanResult('unchanged.example.com', 'not_vulnerable'),
      createScanResult('will-resolve.example.com', 'not_vulnerable'),
      createScanResult('will-change.example.com', 'vulnerable', 'Heroku'),
      createScanResult('new-vuln.example.com', 'vulnerable', 'GitHub Pages'),
    ]);

    const diff = compareScans(baseline, current);

    // new-vuln is new vulnerable (treated as new since was safe→risky)
    // will-change went from likely→vulnerable (changed between risky states)
    // will-resolve went from vulnerable→safe (resolved)
    // unchanged stayed safe
    // removed-safe was safe, now gone (not counted as resolved since it was safe)

    expect(diff.summary.unchanged).toBe(1);  // unchanged
    expect(diff.summary.resolved).toBe(1);   // will-resolve
    expect(diff.summary.statusChanged).toBe(1); // will-change (both risky)
    expect(diff.summary.newVulnerable).toBe(1);  // new-vuln
  });
});

describe('getDiffExitCode', () => {
  it('should return 0 when no new vulnerabilities', () => {
    const diff: DiffResult = {
      version: '0.6.0',
      timestamp: new Date().toISOString(),
      baseline: { timestamp: '', total: 1 },
      current: { timestamp: '', total: 1 },
      summary: {
        newVulnerable: 0,
        newLikely: 0,
        newPotential: 0,
        resolved: 1,
        unchanged: 0,
        statusChanged: 0,
      },
      entries: [],
    };

    expect(getDiffExitCode(diff)).toBe(0);
  });

  it('should return 1 when new likely vulnerabilities', () => {
    const diff: DiffResult = {
      version: '0.6.0',
      timestamp: new Date().toISOString(),
      baseline: { timestamp: '', total: 1 },
      current: { timestamp: '', total: 2 },
      summary: {
        newVulnerable: 0,
        newLikely: 1,
        newPotential: 0,
        resolved: 0,
        unchanged: 1,
        statusChanged: 0,
      },
      entries: [],
    };

    expect(getDiffExitCode(diff)).toBe(1);
  });

  it('should return 2 when new vulnerable findings', () => {
    const diff: DiffResult = {
      version: '0.6.0',
      timestamp: new Date().toISOString(),
      baseline: { timestamp: '', total: 1 },
      current: { timestamp: '', total: 2 },
      summary: {
        newVulnerable: 1,
        newLikely: 1,
        newPotential: 0,
        resolved: 0,
        unchanged: 0,
        statusChanged: 0,
      },
      entries: [],
    };

    expect(getDiffExitCode(diff)).toBe(2);
  });

  it('should return 0 when only potential vulnerabilities', () => {
    const diff: DiffResult = {
      version: '0.6.0',
      timestamp: new Date().toISOString(),
      baseline: { timestamp: '', total: 0 },
      current: { timestamp: '', total: 1 },
      summary: {
        newVulnerable: 0,
        newLikely: 0,
        newPotential: 5,
        resolved: 0,
        unchanged: 0,
        statusChanged: 0,
      },
      entries: [],
    };

    expect(getDiffExitCode(diff)).toBe(0);
  });
});

describe('formatDiffText', () => {
  it('should format empty diff', () => {
    const diff: DiffResult = {
      version: '0.6.0',
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

    const text = formatDiffText(diff);
    expect(text).toContain('SubVet Diff Report');
    expect(text).toContain('Unchanged:       10');
    expect(text).toContain('No Changes');
    expect(text).toContain('No new vulnerabilities');
  });

  it('should format diff with new vulnerabilities', () => {
    const diff: DiffResult = {
      version: '0.6.0',
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
          subdomain: 'vuln.example.com',
          type: 'new',
          currentStatus: 'vulnerable',
          service: 'AWS S3',
          evidence: ['NoSuchBucket error'],
          risk: 'critical',
        },
      ],
    };

    const text = formatDiffText(diff);
    expect(text).toContain('New vulnerable:  1');
    expect(text).toContain('NEW: vuln.example.com');
    expect(text).toContain('VULNERABLE');
    expect(text).toContain('AWS S3');
  });

  it('should format diff with resolved issues', () => {
    const diff: DiffResult = {
      version: '0.6.0',
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
          service: 'Heroku',
        },
      ],
    };

    const text = formatDiffText(diff);
    expect(text).toContain('Resolved:        1');
    expect(text).toContain('RESOLVED: fixed.example.com');
    expect(text).toContain('Was: VULNERABLE');
  });
});
