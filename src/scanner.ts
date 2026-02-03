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
import { escapeRegex } from './utils.js';

const VERSION = '0.5.0';

export class Scanner {
  private dnsResolver: DnsResolver;
  private httpProber: HttpProber;
  private options: ScanOptions;

  constructor(options: Partial<ScanOptions> = {}) {
    this.options = {
      timeout: options.timeout ?? 10000,
      concurrency: options.concurrency ?? 10,
      httpProbe: options.httpProbe ?? true,
      nsCheck: options.nsCheck ?? false,
      mxCheck: options.mxCheck ?? false,
      spfCheck: options.spfCheck ?? false,
      srvCheck: options.srvCheck ?? false,
      verbose: options.verbose ?? false,
      output: options.output
    };

    this.dnsResolver = new DnsResolver({ 
      timeout: this.options.timeout,
      checkNs: this.options.nsCheck,
      checkMx: this.options.mxCheck,
      checkSpf: this.options.spfCheck,
      checkSrv: this.options.srvCheck
    });
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
        hasIpv4: false,
        hasIpv6: false,
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

    // Step 3: Check DNS fingerprint rules (dns_nxdomain, dns_cname)
    if (matchedService) {
      const dnsMatches = this.checkDnsFingerprints(matchedService, result.dns, result.cname);
      if (dnsMatches.length > 0) {
        result.evidence.push(...dnsMatches);
        
        if (matchedService.takeoverPossible) {
          // DNS match alone is "likely", not "vulnerable" (needs HTTP confirmation)
          if (result.status === 'unknown') {
            result.status = 'likely';
            result.risk = 'high';
            result.poc = matchedService.poc;
          }
        } else {
          result.status = 'potential';
          result.risk = 'medium';
        }
      }
    }

    // Legacy NXDOMAIN check for services without explicit dns_nxdomain rule
    if (result.dns.nxdomain && result.cname && result.status === 'unknown') {
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
        const { matches, confidence, requiredMet, negativeMatch } = this.checkFingerprints(matchedService, result.http);
        const minConfidence = matchedService.minConfidence ?? 3;
        
        if (matches.length > 0) {
          result.evidence.push(...matches);
          result.evidence.push(`Confidence: ${confidence}/10`);
          
          // Negative pattern matched = safe
          if (negativeMatch) {
            result.status = 'not_vulnerable';
            result.risk = 'info';
          } else if (!requiredMet) {
            // Required rules not met = potential only
            result.status = 'potential';
            result.risk = 'low';
            result.evidence.push('Required fingerprint not matched');
          } else if (matchedService.takeoverPossible) {
            if (confidence >= 7) {
              // High confidence: multiple strong indicators
              result.status = 'vulnerable';
              result.risk = 'critical';
            } else if (confidence >= minConfidence) {
              // Medium confidence: some indicators
              result.status = 'likely';
              result.risk = 'high';
            } else {
              // Low confidence: weak indicators only
              result.status = 'potential';
              result.risk = 'medium';
            }
            result.poc = matchedService.poc;
          } else {
            result.status = 'potential';
            result.risk = 'medium';
          }
        }
      }

      // Generic checks for unrecognized services
      if (!matchedService && result.http.body) {
        const genericChecks = this.checkGenericPatterns(result.http.body, result.http.status);
        if (genericChecks.length > 0) {
          result.evidence.push(...genericChecks);
          result.status = 'potential';
          result.risk = 'medium';
        }
      }
    }

    // Step 5: Check for dangling NS delegation
    if (result.dns.nsDangling && result.dns.nsDangling.length > 0) {
      result.evidence.push(`Dangling NS delegation: ${result.dns.nsDangling.join(', ')}`);
      result.status = 'vulnerable';
      result.risk = 'critical';
      result.service = 'NS Delegation';
      result.poc = 'Register the dangling nameserver domain and configure DNS zone';
    }

    // Step 5b: Check for dangling MX records
    if (result.dns.mxDangling && result.dns.mxDangling.length > 0) {
      result.evidence.push(`Dangling MX record: ${result.dns.mxDangling.join(', ')}`);
      // MX takeover is critical - allows email interception
      if (result.status !== 'vulnerable') {
        result.status = 'vulnerable';
        result.risk = 'critical';
        result.service = 'MX Record';
        result.poc = 'Register the dangling mail server domain to intercept emails';
      }
    }

    // Step 5c: Check for dangling SPF includes
    if (result.dns.spfDangling && result.dns.spfDangling.length > 0) {
      result.evidence.push(`Dangling SPF include: ${result.dns.spfDangling.join(', ')}`);
      // SPF bypass allows phishing
      if (result.status !== 'vulnerable') {
        result.status = 'vulnerable';
        result.risk = 'high';
        result.service = 'SPF Record';
        result.poc = 'Register the dangling domain and create SPF record to bypass email authentication';
      }
    }

    // Step 5d: Check for dangling SRV records
    if (result.dns.srvDangling && result.dns.srvDangling.length > 0) {
      result.evidence.push(`Dangling SRV record: ${result.dns.srvDangling.join(', ')}`);
      // SRV takeover can hijack services like autodiscover, SIP, etc.
      if (result.status !== 'vulnerable') {
        result.status = 'vulnerable';
        result.risk = 'high';
        result.service = 'SRV Record';
        result.poc = 'Register the dangling domain and configure the service to intercept traffic';
      }
    }

    // Step 6: Finalize status
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
   * Returns { matches, confidence, requiredMet }
   * - confidence: 0-10 score based on matched rules
   * - requiredMet: true if all required rules matched
   */
  private checkFingerprints(
    service: ServiceFingerprint,
    http: { status: number | null; body: string | null; headers: Record<string, string> }
  ): { matches: string[]; confidence: number; requiredMet: boolean; negativeMatch: boolean } {
    const matches: string[] = [];
    let totalWeight = 0;
    let matchedWeight = 0;
    const requiredRules: { rule: FingerprintRule; matched: boolean }[] = [];

    // Check positive patterns
    for (const rule of service.fingerprints) {
      const weight = rule.weight ?? 5;
      totalWeight += weight;
      let matched = false;

      switch (rule.type) {
        case 'http_body':
          if (http.body && rule.pattern) {
            const pattern = rule.pattern instanceof RegExp 
              ? rule.pattern 
              : new RegExp(escapeRegex(String(rule.pattern)), 'i');
            
            if (pattern.test(http.body)) {
              matches.push(`HTTP body matches: "${rule.pattern}"`);
              matchedWeight += weight;
              matched = true;
            }
          }
          break;

        case 'http_status':
          if (http.status === rule.value) {
            matches.push(`HTTP status: ${rule.value}`);
            matchedWeight += weight;
            matched = true;
          }
          break;

        case 'http_header':
          if (rule.header && rule.pattern) {
            const headerValue = http.headers[rule.header.toLowerCase()];
            if (headerValue) {
              const pattern = rule.pattern instanceof RegExp
                ? rule.pattern
                : new RegExp(escapeRegex(String(rule.pattern)), 'i');
              
              if (pattern.test(headerValue)) {
                matches.push(`HTTP header ${rule.header} matches: "${rule.pattern}"`);
                matchedWeight += weight;
                matched = true;
              }
            }
          }
          break;

        case 'dns_nxdomain':
          // Handled in DNS phase
          break;
      }

      if (rule.required) {
        requiredRules.push({ rule, matched });
      }
    }

    // Check negative patterns (if any match, it's NOT vulnerable)
    let negativeMatch = false;
    if (service.negativePatterns) {
      for (const neg of service.negativePatterns) {
        switch (neg.type) {
          case 'http_body':
            if (http.body && neg.pattern) {
              const pattern = neg.pattern instanceof RegExp
                ? neg.pattern
                : new RegExp(escapeRegex(String(neg.pattern)), 'i');
              if (pattern.test(http.body)) {
                matches.push(`Safe: ${neg.description}`);
                negativeMatch = true;
              }
            }
            break;
          case 'http_status':
            if (http.status === neg.value) {
              matches.push(`Safe: ${neg.description}`);
              negativeMatch = true;
            }
            break;
          case 'http_header':
            if (neg.header) {
              const headerValue = http.headers[neg.header.toLowerCase()];
              if (headerValue && neg.pattern) {
                const pattern = neg.pattern instanceof RegExp
                  ? neg.pattern
                  : new RegExp(escapeRegex(String(neg.pattern)), 'i');
                if (pattern.test(headerValue)) {
                  matches.push(`Safe: ${neg.description}`);
                  negativeMatch = true;
                }
              }
            }
            break;
        }
      }
    }

    // Calculate confidence (0-10 scale)
    const confidence = totalWeight > 0 ? Math.round((matchedWeight / totalWeight) * 10) : 0;

    // Check if all required rules matched
    const requiredMet = requiredRules.length === 0 || requiredRules.every(r => r.matched);

    return { matches, confidence, requiredMet, negativeMatch };
  }

  /**
   * Check DNS fingerprint rules (dns_nxdomain, dns_cname)
   */
  private checkDnsFingerprints(
    service: ServiceFingerprint,
    dns: { nxdomain: boolean; cname?: string },
    cname: string | null
  ): string[] {
    const matches: string[] = [];

    for (const rule of service.fingerprints) {
      switch (rule.type) {
        case 'dns_nxdomain':
          if (dns.nxdomain) {
            matches.push('DNS: CNAME target returns NXDOMAIN');
          }
          break;

        case 'dns_cname':
          if (cname && rule.pattern) {
            const pattern = rule.pattern instanceof RegExp
              ? rule.pattern
              : new RegExp(escapeRegex(String(rule.pattern)), 'i');
            
            if (pattern.test(cname)) {
              matches.push(`DNS: CNAME matches pattern "${rule.pattern}"`);
            }
          }
          break;
      }
    }

    return matches;
  }

  /**
   * Check generic patterns that might indicate takeover
   * Now with stronger compound matching
   */
  private checkGenericPatterns(body: string, status: number | null): string[] {
    const patterns: string[] = [];
    
    // Strong indicators (high confidence alone)
    const strongIndicators = [
      { pattern: /NoSuchBucket/i, desc: 'AWS S3 NoSuchBucket' },
      { pattern: /bucket.*does.*not.*exist/i, desc: 'Bucket does not exist' },
      { pattern: /domain.*not.*configured/i, desc: 'Domain not configured' },
      { pattern: /no.*such.*app/i, desc: 'No such app' },
      { pattern: /This.*subdomain.*is.*currently.*available/i, desc: 'Subdomain available' },
      { pattern: /unclaimed/i, desc: 'Unclaimed resource' },
      { pattern: /DEPLOYMENT_NOT_FOUND/i, desc: 'Deployment not found' }
    ];

    // Weak indicators (need status code to confirm)
    const weakIndicators = [
      { pattern: /site.*not.*found/i, desc: 'Site not found', needsStatus: [404, 410] },
      { pattern: /project.*not.*found/i, desc: 'Project not found', needsStatus: [404] },
      { pattern: /repository.*not.*found/i, desc: 'Repository not found', needsStatus: [404] },
      { pattern: /page.*does.*not.*exist/i, desc: 'Page does not exist', needsStatus: [404, 410] },
      { pattern: /there.*is.*nothing.*here/i, desc: 'Nothing here message', needsStatus: [404] }
    ];

    // Safe patterns (skip if these are present)
    const safePatterns = [
      /maintenance/i,
      /coming.*soon/i,
      /under.*construction/i,
      /please.*log.*in/i,
      /sign.*in.*required/i,
      /authentication.*required/i
    ];

    // Check safe patterns first
    for (const safe of safePatterns) {
      if (safe.test(body)) {
        return []; // Not vulnerable, skip generic checks
      }
    }

    // Check strong indicators
    for (const { pattern, desc } of strongIndicators) {
      if (pattern.test(body)) {
        patterns.push(`Strong indicator: ${desc}`);
      }
    }

    // Check weak indicators (only if status matches)
    for (const { pattern, desc, needsStatus } of weakIndicators) {
      if (pattern.test(body) && status !== null && needsStatus.includes(status)) {
        patterns.push(`Indicator: ${desc} (status ${status})`);
      }
    }

    return patterns;
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
