/**
 * SubVet - Main Scanner Module
 */

import type {
  ScanResult,
  ScanOptions,
  ScanOutput,
  ScanSummary,
  ServiceFingerprint
} from './types.js';
import { DnsResolver, type WildcardResult } from './dns.js';
import { HttpProber } from './http.js';
import { findServiceByCname, fingerprints } from './fingerprints/index.js';
import { VERSION } from './version.js';
import { getDomain } from 'tldts';
import {
  checkFingerprints,
  checkDnsFingerprints,
  checkGenericPatterns,
  checkStaleCname,
} from './fingerprint-checker.js';
import { applyWildcardAdjustment } from './wildcard.js';
import {
  SCAN_TIMEOUT_MS,
  DEFAULT_CONCURRENCY,
  CONFIDENCE_VULNERABLE,
  CONFIDENCE_DEFAULT_MIN,
  CONFIDENCE_SCALE,
} from './constants.js';

/**
 * Extract the registrable domain (eTLD+1) from a hostname.
 * Handles multi-part TLDs like co.uk, com.au correctly.
 */
export function getRegistrableDomain(host: string): string {
  const registrable = getDomain(host, { allowPrivateDomains: false });
  if (registrable) return registrable;
  // Fallback for unusual inputs
  const parts = host.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

export class Scanner {
  private dnsResolver: DnsResolver;
  private httpProber: HttpProber;
  private options: ScanOptions;

  constructor(options: Partial<ScanOptions> = {}) {
    this.options = {
      timeout: options.timeout ?? SCAN_TIMEOUT_MS,
      concurrency: options.concurrency ?? DEFAULT_CONCURRENCY,
      httpProbe: options.httpProbe ?? true,
      nsCheck: options.nsCheck ?? false,
      mxCheck: options.mxCheck ?? false,
      spfCheck: options.spfCheck ?? false,
      srvCheck: options.srvCheck ?? false,
      txtCheck: options.txtCheck ?? false,
      verbose: options.verbose ?? false,
      output: options.output
    };

    this.dnsResolver = new DnsResolver({ 
      timeout: this.options.timeout,
      checkNs: this.options.nsCheck,
      checkMx: this.options.mxCheck,
      checkSpf: this.options.spfCheck,
      checkSrv: this.options.srvCheck,
      checkTxt: this.options.txtCheck
    });
    this.httpProber = new HttpProber({ timeout: this.options.timeout });
  }

  /**
   * Scan a single subdomain, optionally with pre-computed wildcard info
   */
  async scanOne(subdomain: string, wildcardInfo?: WildcardResult): Promise<ScanResult> {
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
      const dnsMatches = checkDnsFingerprints(matchedService, result.dns, result.cname);
      if (dnsMatches.length > 0) {
        result.evidence.push(...dnsMatches);
        
        if (matchedService.takeoverPossible) {
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

      if (matchedService && result.http) {
        const { matches, confidence, requiredMet, negativeMatch } = checkFingerprints(matchedService, result.http);
        const minConfidence = matchedService.minConfidence ?? CONFIDENCE_DEFAULT_MIN;
        
        if (matches.length > 0) {
          result.evidence.push(...matches);
          result.evidence.push(`Confidence: ${confidence}/${CONFIDENCE_SCALE}`);
          
          if (negativeMatch) {
            result.status = 'not_vulnerable';
            result.risk = 'info';
          } else if (!requiredMet) {
            result.status = 'potential';
            result.risk = 'low';
            result.evidence.push('Required fingerprint not matched');
          } else if (matchedService.takeoverPossible) {
            if (confidence >= CONFIDENCE_VULNERABLE) {
              result.status = 'vulnerable';
              result.risk = 'critical';
            } else if (confidence >= minConfidence) {
              result.status = 'likely';
              result.risk = 'high';
            } else {
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
      if (!matchedService && result.http?.body) {
        const genericChecks = checkGenericPatterns(result.http.body, result.http.status);
        if (genericChecks.length > 0) {
          result.evidence.push(...genericChecks);
          result.status = 'potential';
          result.risk = 'medium';
        }
      }

      // Step 4c: Stale CNAME detection (generic)
      if (result.cname && (result.status === 'not_vulnerable' || result.status === 'unknown')) {
        if (result.http) {
          const staleChecks = checkStaleCname(result.cname, result.http, result.dns.nxdomain);
          if (staleChecks.length > 0) {
            result.evidence.push(...staleChecks);
            result.status = 'potential';
            result.risk = 'medium';
            result.service = result.service ?? 'Stale CNAME';
          }
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
      if (result.status !== 'vulnerable') {
        result.status = 'vulnerable';
        result.risk = 'high';
        result.service = 'SRV Record';
        result.poc = 'Register the dangling domain and configure the service to intercept traffic';
      }
    }

    // Step 5e: Check for dangling TXT domain references
    if (result.dns.txtDangling && result.dns.txtDangling.length > 0) {
      result.evidence.push(`Dangling TXT domain reference: ${result.dns.txtDangling.join(', ')}`);
      if (result.status !== 'vulnerable') {
        result.status = 'potential';
        result.risk = 'medium';
        result.service = result.service ?? 'TXT Record';
        result.poc = 'Register the dangling domain referenced in TXT records to potentially bypass SPF or claim verification';
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

    // Step 7: Wildcard DNS adjustment
    if (wildcardInfo?.isWildcard) {
      applyWildcardAdjustment(result, wildcardInfo);
    }

    return result;
  }

  /**
   * Scan multiple subdomains
   */
  async scan(subdomains: string[]): Promise<ScanOutput> {
    const results: ScanResult[] = [];
    const batchSize = this.options.concurrency;

    // Pre-scan: check wildcard DNS for each unique base domain
    const wildcardCache = new Map<string, WildcardResult>();
    const baseDomains = new Set<string>();
    for (const sub of subdomains) {
      const base = getRegistrableDomain(sub);
      baseDomains.add(base);
    }
    await Promise.all(
      [...baseDomains].map(async (base) => {
        try {
          const result = await this.dnsResolver.checkWildcard(base);
          wildcardCache.set(base, result);
        } catch (err) {
          wildcardCache.set(base, { isWildcard: false });
          if (this.options.verbose) {
            process.stderr.write(`\nWarning: wildcard check failed for ${base}: ${(err as Error).message}\n`);
          }
        }
      })
    );

    // Process in batches
    for (let i = 0; i < subdomains.length; i += batchSize) {
      const batch = subdomains.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(subdomain => {
          const base = getRegistrableDomain(subdomain);
          return this.scanOne(subdomain, wildcardCache.get(base));
        })
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
