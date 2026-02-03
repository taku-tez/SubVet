/**
 * SubVet - Main Scanner Module
 */

import type {
  ScanResult,
  ScanOptions,
  ScanOutput,
  ScanSummary,
  FingerprintRule,
  ServiceFingerprint
} from './types.js';
import { DnsResolver } from './dns.js';
import { HttpProber } from './http.js';
import { findServiceByCname, fingerprints } from './fingerprints/index.js';

const VERSION = '0.1.0';

export class Scanner {
  private dnsResolver: DnsResolver;
  private httpProber: HttpProber;
  private options: ScanOptions;

  constructor(options: Partial<ScanOptions> = {}) {
    this.options = {
      timeout: options.timeout ?? 10000,
      concurrency: options.concurrency ?? 10,
      httpProbe: options.httpProbe ?? true,
      verbose: options.verbose ?? false,
      output: options.output
    };

    this.dnsResolver = new DnsResolver({ timeout: this.options.timeout });
    this.httpProber = new HttpProber({ timeout: this.options.timeout });
  }

  /**
   * Scan a single subdomain
   */
  async scanOne(subdomain: string): Promise<ScanResult> {
    const result: ScanResult = {
      subdomain,
      status: 'unknown',
      service: null,
      cname: null,
      evidence: [],
      risk: 'info',
      dns: {
        subdomain,
        records: [],
        resolved: false,
        nxdomain: false
      },
      timestamp: new Date().toISOString()
    };

    // Step 1: DNS Resolution
    result.dns = await this.dnsResolver.resolve(subdomain);
    result.cname = result.dns.cname ?? null;

    // Step 2: Check if CNAME matches known services
    let matchedService: ServiceFingerprint | null = null;
    if (result.cname) {
      matchedService = findServiceByCname(result.cname);
      if (matchedService) {
        result.service = matchedService.service;
        result.evidence.push(`CNAME points to ${matchedService.service}: ${result.cname}`);
      }
    }

    // Step 3: Check for NXDOMAIN on CNAME target
    if (result.dns.nxdomain && result.cname) {
      result.evidence.push('CNAME target returns NXDOMAIN');
      
      if (matchedService?.takeoverPossible) {
        result.status = 'likely';
        result.risk = 'high';
        result.poc = matchedService.poc;
      } else {
        result.status = 'potential';
        result.risk = 'medium';
      }
    }

    // Step 4: HTTP Probe (if enabled)
    if (this.options.httpProbe && (result.dns.resolved || result.dns.nxdomain)) {
      result.http = await this.httpProber.probe(subdomain);

      if (matchedService && result.http.body) {
        const matches = this.checkFingerprints(matchedService.fingerprints, result.http);
        
        if (matches.length > 0) {
          result.evidence.push(...matches);
          
          if (matchedService.takeoverPossible) {
            result.status = 'vulnerable';
            result.risk = 'critical';
            result.poc = matchedService.poc;
          } else {
            result.status = 'potential';
            result.risk = 'medium';
          }
        }
      }

      // Generic checks for unrecognized services
      if (!matchedService && result.http.body) {
        const genericChecks = this.checkGenericPatterns(result.http.body);
        if (genericChecks.length > 0) {
          result.evidence.push(...genericChecks);
          result.status = 'potential';
          result.risk = 'medium';
        }
      }
    }

    // Step 5: Finalize status
    if (result.status === 'unknown') {
      if (result.dns.resolved) {
        result.status = 'not_vulnerable';
        result.risk = 'info';
      } else if (result.dns.error) {
        result.evidence.push(`DNS error: ${result.dns.error}`);
      }
    }

    return result;
  }

  /**
   * Check fingerprint rules against HTTP response
   */
  private checkFingerprints(rules: FingerprintRule[], http: { status: number | null; body: string | null; headers: Record<string, string> }): string[] {
    const matches: string[] = [];

    for (const rule of rules) {
      switch (rule.type) {
        case 'http_body':
          if (http.body && rule.pattern) {
            const pattern = rule.pattern instanceof RegExp 
              ? rule.pattern 
              : new RegExp(this.escapeRegex(String(rule.pattern)), 'i');
            
            if (pattern.test(http.body)) {
              matches.push(`HTTP body matches: "${rule.pattern}"`);
            }
          }
          break;

        case 'http_status':
          if (http.status === rule.value) {
            matches.push(`HTTP status: ${rule.value}`);
          }
          break;

        case 'http_header':
          if (rule.header && rule.pattern) {
            const headerValue = http.headers[rule.header.toLowerCase()];
            if (headerValue) {
              const pattern = rule.pattern instanceof RegExp
                ? rule.pattern
                : new RegExp(this.escapeRegex(String(rule.pattern)), 'i');
              
              if (pattern.test(headerValue)) {
                matches.push(`HTTP header ${rule.header} matches: "${rule.pattern}"`);
              }
            }
          }
          break;

        case 'dns_nxdomain':
          // Handled in DNS phase
          break;
      }
    }

    return matches;
  }

  /**
   * Check generic patterns that might indicate takeover
   */
  private checkGenericPatterns(body: string): string[] {
    const patterns: string[] = [];
    
    const genericIndicators = [
      { pattern: /domain.*not.*configured/i, desc: 'Domain not configured' },
      { pattern: /no.*such.*app/i, desc: 'No such app' },
      { pattern: /site.*not.*found/i, desc: 'Site not found' },
      { pattern: /page.*does.*not.*exist/i, desc: 'Page does not exist' },
      { pattern: /project.*not.*found/i, desc: 'Project not found' },
      { pattern: /repository.*not.*found/i, desc: 'Repository not found' },
      { pattern: /bucket.*does.*not.*exist/i, desc: 'Bucket does not exist' },
      { pattern: /NoSuchBucket/i, desc: 'NoSuchBucket error' },
      { pattern: /there.*is.*nothing.*here/i, desc: 'Nothing here message' },
      { pattern: /unclaimed/i, desc: 'Unclaimed resource' }
    ];

    for (const { pattern, desc } of genericIndicators) {
      if (pattern.test(body)) {
        patterns.push(`Generic indicator: ${desc}`);
      }
    }

    return patterns;
  }

  /**
   * Escape regex special characters
   */
  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Scan multiple subdomains
   */
  async scan(subdomains: string[]): Promise<ScanOutput> {
    const results: ScanResult[] = [];
    const batchSize = this.options.concurrency;

    // Process in batches
    for (let i = 0; i < subdomains.length; i += batchSize) {
      const batch = subdomains.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(subdomain => this.scanOne(subdomain))
      );
      results.push(...batchResults);

      if (this.options.verbose) {
        const progress = Math.min(i + batchSize, subdomains.length);
        process.stderr.write(`\rProgress: ${progress}/${subdomains.length}`);
      }
    }

    if (this.options.verbose) {
      process.stderr.write('\n');
    }

    // Calculate summary
    const summary: ScanSummary = {
      total: results.length,
      vulnerable: results.filter(r => r.status === 'vulnerable').length,
      likely: results.filter(r => r.status === 'likely').length,
      potential: results.filter(r => r.status === 'potential').length,
      safe: results.filter(r => r.status === 'not_vulnerable').length,
      errors: results.filter(r => r.dns.error !== undefined).length
    };

    return {
      version: VERSION,
      timestamp: new Date().toISOString(),
      target: subdomains.length === 1 ? subdomains[0] : `${subdomains.length} subdomains`,
      options: this.options,
      summary,
      results
    };
  }
}

/**
 * Quick scan helper
 */
export async function quickScan(subdomains: string[], options?: Partial<ScanOptions>): Promise<ScanOutput> {
  const scanner = new Scanner(options);
  return scanner.scan(subdomains);
}

/**
 * List all supported services
 */
export function listServices(): { service: string; takeoverPossible: boolean }[] {
  return fingerprints.map(fp => ({
    service: fp.service,
    takeoverPossible: fp.takeoverPossible
  }));
}
