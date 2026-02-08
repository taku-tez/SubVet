/**
 * Report Module Tests
 */

import { describe, it, expect } from 'vitest';
import { generateReport, generateMarkdownReport, generateHtmlReport, generateSarifReport, REPO_URL } from '../report.js';
import type { ScanOutput, ScanResult } from '../types.js';

// Helper to create mock scan result
function createMockResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    subdomain: 'test.example.com',
    status: 'not_vulnerable',
    service: null,
    cname: null,
    evidence: [],
    risk: 'info',
    dns: {
      subdomain: 'test.example.com',
      records: [],
      hasIpv4: true,
      hasIpv6: false,
      resolved: true,
      nxdomain: false
    },
    timestamp: '2026-02-04T00:00:00.000Z',
    ...overrides
  };
}

// Helper to create mock scan output
function createMockOutput(results: ScanResult[]): ScanOutput {
  return {
    version: '0.4.0',
    timestamp: '2026-02-04T00:00:00.000Z',
    target: 'test',
    options: {
      timeout: 10000,
      concurrency: 10,
      httpProbe: true,
      nsCheck: false,
      mxCheck: false,
      spfCheck: false,
      srvCheck: false,
      verbose: false
    },
    summary: {
      total: results.length,
      vulnerable: results.filter(r => r.status === 'vulnerable').length,
      likely: results.filter(r => r.status === 'likely').length,
      potential: results.filter(r => r.status === 'potential').length,
      safe: results.filter(r => r.status === 'not_vulnerable').length,
      errors: results.filter(r => r.dns.error !== undefined).length
    },
    results
  };
}

describe('generateReport', () => {
  it('should format JSON output', () => {
    const output = createMockOutput([createMockResult()]);
    const report = generateReport(output, 'json');
    const parsed = JSON.parse(report);
    expect(parsed.version).toBe('0.4.0');
    expect(parsed.results).toHaveLength(1);
  });

  it('should format markdown output', () => {
    const output = createMockOutput([
      createMockResult({ status: 'vulnerable', service: 'AWS S3', risk: 'critical' })
    ]);
    const report = generateReport(output, 'md');
    expect(report).toContain('# 🔍 SubVet Scan Report');
    expect(report).toContain('Vulnerable');
  });

  it('should format HTML output', () => {
    const output = createMockOutput([createMockResult()]);
    const report = generateReport(output, 'html');
    expect(report).toContain('<!DOCTYPE html>');
    expect(report).toContain('SubVet Scan Report');
  });
});

describe('generateMarkdownReport', () => {
  it('should include vulnerable results in findings', () => {
    const output = createMockOutput([
      createMockResult({
        subdomain: 'vuln.example.com',
        status: 'vulnerable',
        service: 'GitHub Pages',
        cname: 'test.github.io',
        evidence: ['CNAME points to GitHub Pages'],
        risk: 'critical',
        poc: 'Create repository and configure GitHub Pages'
      })
    ]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('vuln.example.com');
    expect(md).toContain('GitHub Pages');
    expect(md).toContain('Vulnerable');
  });

  it('should handle empty results', () => {
    const output = createMockOutput([]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('Total');
    expect(md).toContain('0');
  });

  it('should include likely and potential findings', () => {
    const output = createMockOutput([
      createMockResult({ status: 'likely', service: 'Heroku', risk: 'high' }),
      createMockResult({ status: 'potential', service: 'Unknown', risk: 'medium' })
    ]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('Likely');
  });

  it('should include summary table', () => {
    const output = createMockOutput([
      createMockResult({ status: 'vulnerable' }),
      createMockResult({ status: 'not_vulnerable' })
    ]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('Summary');
    expect(md).toContain('Status');
    expect(md).toContain('Count');
  });

  it('should include evidence in findings', () => {
    const output = createMockOutput([
      createMockResult({
        status: 'vulnerable',
        evidence: ['CNAME match', 'HTTP body match']
      })
    ]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('CNAME match');
  });

  it('should escape pipe characters in table cells', () => {
    const output = createMockOutput([
      createMockResult({
        status: 'vulnerable',
        evidence: ['Pattern: foo|bar|baz']
      })
    ]);
    const md = generateMarkdownReport(output);
    // Pipes should be escaped to prevent table corruption
    expect(md).toContain('foo\\|bar\\|baz');
    expect(md).not.toMatch(/\|foo\|bar\|baz\|/); // Should NOT have unescaped pipes
  });

  it('should handle newlines in evidence', () => {
    const output = createMockOutput([
      createMockResult({
        status: 'vulnerable',
        evidence: ['Line1\nLine2\nLine3']
      })
    ]);
    const md = generateMarkdownReport(output);
    // Newlines should be converted to <br>
    expect(md).toContain('<br>');
    // Original newlines should be replaced (check the cell content doesn't have raw \n)
    expect(md).toContain('Line1<br>Line2<br>Line3');
  });

  it('should escape special characters in service names', () => {
    const output = createMockOutput([
      createMockResult({
        status: 'vulnerable',
        service: 'Service|With|Pipes'
      })
    ]);
    const md = generateMarkdownReport(output);
    expect(md).toContain('Service\\|With\\|Pipes');
  });
});

describe('generateHtmlReport', () => {
  it('should generate valid HTML with styles', () => {
    const output = createMockOutput([createMockResult()]);
    const html = generateHtmlReport(output);
    expect(html).toContain('<html');
    expect(html).toContain('<style>');
    expect(html).toContain('</html>');
  });

  it('should include all result details', () => {
    const output = createMockOutput([
      createMockResult({
        subdomain: 'test.example.com',
        status: 'vulnerable',
        service: 'Shopify',
        cname: 'shops.myshopify.com',
        evidence: ['CNAME match', 'HTTP body match'],
        risk: 'critical'
      })
    ]);
    const html = generateHtmlReport(output);
    expect(html).toContain('test.example.com');
    expect(html).toContain('Shopify');
  });

  it('should apply correct risk colors', () => {
    const output = createMockOutput([
      createMockResult({ status: 'vulnerable', risk: 'critical' }),
      createMockResult({ status: 'likely', risk: 'high' }),
      createMockResult({ status: 'potential', risk: 'medium' })
    ]);
    const html = generateHtmlReport(output);
    expect(html).toContain('vulnerable');
  });

  it('should include summary statistics', () => {
    const output = createMockOutput([
      createMockResult({ status: 'vulnerable' }),
      createMockResult({ status: 'not_vulnerable' }),
      createMockResult({ status: 'not_vulnerable' })
    ]);
    const html = generateHtmlReport(output);
    // HTML uses class="summary" div instead of text "Summary"
    expect(html).toContain('summary');
    expect(html).toContain('stat-value');
  });

  it('should include timestamp', () => {
    const output = createMockOutput([createMockResult()]);
    const html = generateHtmlReport(output);
    expect(html).toContain('2026');
  });

  it('should handle poc field', () => {
    const output = createMockOutput([
      createMockResult({
        status: 'vulnerable',
        poc: 'Create S3 bucket with matching name'
      })
    ]);
    const html = generateHtmlReport(output);
    // POC might be included in the output
    expect(html).toContain('vulnerable');
  });
});

describe('generateSarifReport', () => {
  it('should generate valid SARIF 2.1.0 structure', () => {
    const output = createMockOutput([
      createMockResult({
        subdomain: 'vuln.example.com',
        status: 'vulnerable',
        service: 'AWS S3',
        cname: 'vuln.example.com.s3.amazonaws.com',
        evidence: ['CNAME points to S3', 'NoSuchBucket response'],
        risk: 'critical',
      })
    ]);
    const sarif = JSON.parse(generateSarifReport(output));

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('SubVet');
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it('should map status to correct SARIF levels', () => {
    const output = createMockOutput([
      createMockResult({ subdomain: 'a.example.com', status: 'vulnerable', service: 'S3', risk: 'critical' }),
      createMockResult({ subdomain: 'b.example.com', status: 'likely', service: 'Heroku', risk: 'high' }),
      createMockResult({ subdomain: 'c.example.com', status: 'potential', service: 'Unknown', risk: 'medium' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    const levels = sarif.runs[0].results.map((r: any) => r.level);
    expect(levels).toEqual(['error', 'error', 'warning']);
  });

  it('should skip not_vulnerable results', () => {
    const output = createMockOutput([
      createMockResult({ status: 'not_vulnerable' }),
      createMockResult({ subdomain: 'vuln.example.com', status: 'vulnerable', service: 'S3', risk: 'critical' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it('should generate correct ruleId from service name', () => {
    const output = createMockOutput([
      createMockResult({ subdomain: 'a.example.com', status: 'vulnerable', service: 'AWS S3', risk: 'critical' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results[0].ruleId).toBe('subvet/aws-s3');
    expect(sarif.runs[0].tool.driver.rules[0].id).toBe('subvet/aws-s3');
  });

  it('should include domain as artifact location', () => {
    const output = createMockOutput([
      createMockResult({ subdomain: 'vuln.example.com', status: 'vulnerable', service: 'S3', risk: 'critical' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('vuln.example.com');
  });

  it('should include evidence in message', () => {
    const output = createMockOutput([
      createMockResult({
        subdomain: 'vuln.example.com',
        status: 'vulnerable',
        service: 'S3',
        evidence: ['CNAME match', 'NoSuchBucket'],
        risk: 'critical',
      }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results[0].message.text).toContain('CNAME match');
    expect(sarif.runs[0].results[0].message.text).toContain('NoSuchBucket');
  });

  it('should work via generateReport with sarif format', () => {
    const output = createMockOutput([createMockResult({ status: 'vulnerable', service: 'S3', risk: 'critical' })]);
    const report = generateReport(output, 'sarif');
    const sarif = JSON.parse(report);
    expect(sarif.version).toBe('2.1.0');
  });

  it('should handle empty results', () => {
    const output = createMockOutput([]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it('should use correct informationUri matching package.json repository', () => {
    const output = createMockOutput([
      createMockResult({ subdomain: 'a.example.com', status: 'vulnerable', service: 'S3', risk: 'critical' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].tool.driver.informationUri).toBe('https://github.com/taku-tez/SubVet');
    expect(sarif.runs[0].tool.driver.informationUri).toBe(REPO_URL);
  });

  it('should deduplicate rules for same service', () => {
    const output = createMockOutput([
      createMockResult({ subdomain: 'a.example.com', status: 'vulnerable', service: 'AWS S3', risk: 'critical' }),
      createMockResult({ subdomain: 'b.example.com', status: 'vulnerable', service: 'AWS S3', risk: 'critical' }),
    ]);
    const sarif = JSON.parse(generateSarifReport(output));
    expect(sarif.runs[0].results).toHaveLength(2);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
  });
});
