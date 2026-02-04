/**
 * SubVet - DNS Resolution Module
 */

import dns from 'node:dns';
import { promisify } from 'node:util';
import type { DnsResult } from './types.js';

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveNs = promisify(dns.resolveNs);
const resolveMx = promisify(dns.resolveMx);
const resolveTxt = promisify(dns.resolveTxt);
const resolveSrv = promisify(dns.resolveSrv);

export interface DnsResolverOptions {
  timeout?: number;
  checkNs?: boolean;
  checkMx?: boolean;
  checkSpf?: boolean;
  checkSrv?: boolean;
}

export class DnsResolver {
  private timeout: number;
  private checkNs: boolean;
  private checkMx: boolean;
  private checkSpf: boolean;
  private checkSrv: boolean;

  constructor(options: DnsResolverOptions = {}) {
    this.timeout = options.timeout ?? 5000;
    this.checkNs = options.checkNs ?? false;
    this.checkMx = options.checkMx ?? false;
    this.checkSpf = options.checkSpf ?? false;
    this.checkSrv = options.checkSrv ?? false;
  }

  /**
   * Resolve DNS records for a subdomain
   */
  async resolve(subdomain: string): Promise<DnsResult> {
    const result: DnsResult = {
      subdomain,
      records: [],
      hasIpv4: false,
      hasIpv6: false,
      resolved: false,
      nxdomain: false
    };

    // Try CNAME first
    let hasCname = false;
    let finalCname: string | null = null;
    try {
      const cnames = await this.withTimeout(resolveCname(subdomain));
      if (cnames && cnames.length > 0) {
        hasCname = true;
        // Normalize CNAME (remove trailing dot if present)
        let currentCname = this.normalizeDomain(cnames[0]);
        result.records.push({ type: 'CNAME', value: currentCname });
        result.resolved = true;

        // Follow CNAME chain
        let chainDepth = 0;
        while (chainDepth < 10) {
          try {
            const nextCnames = await this.withTimeout(resolveCname(currentCname));
            if (nextCnames && nextCnames.length > 0) {
              currentCname = this.normalizeDomain(nextCnames[0]);
              result.records.push({ type: 'CNAME', value: currentCname });
              chainDepth++;
            } else {
              break;
            }
          } catch {
            break;
          }
        }
        // Final CNAME in chain is what we check against fingerprints
        finalCname = currentCname;
        result.cname = currentCname;
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        // No CNAME, that's fine, try A/AAAA
      } else if (error.code === 'SERVFAIL' || error.code === 'ESERVFAIL') {
        result.error = 'DNS server failure';
      } else if (error.message === 'DNS timeout') {
        result.error = 'DNS timeout';
      }
    }

    // Resolve A and AAAA in parallel for performance
    const [ipv4Result, ipv6Result] = await Promise.allSettled([
      this.withTimeout(resolve4(subdomain)),
      this.withTimeout(resolve6(subdomain))
    ]);

    let hasIpv4 = false;
    let hasIpv6 = false;
    let aNotFound = false;
    let aaaaNotFound = false;

    // Process A record result
    if (ipv4Result.status === 'fulfilled' && ipv4Result.value?.length > 0) {
      for (const ip of ipv4Result.value) {
        result.records.push({ type: 'A', value: ip });
      }
      result.resolved = true;
      hasIpv4 = true;
    } else if (ipv4Result.status === 'rejected') {
      const error = ipv4Result.reason as NodeJS.ErrnoException;
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        aNotFound = true;
      } else if (error.message === 'DNS timeout') {
        result.error = result.error || 'DNS timeout';
      } else if (error.code === 'SERVFAIL' || error.code === 'ESERVFAIL') {
        result.error = result.error || 'DNS server failure';
      }
    }

    // Process AAAA record result
    if (ipv6Result.status === 'fulfilled' && ipv6Result.value?.length > 0) {
      for (const ip of ipv6Result.value) {
        result.records.push({ type: 'AAAA', value: ip });
      }
      result.resolved = true;
      hasIpv6 = true;
    } else if (ipv6Result.status === 'rejected') {
      const error = ipv6Result.reason as NodeJS.ErrnoException;
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        aaaaNotFound = true;
      } else if (error.message === 'DNS timeout') {
        result.error = result.error || 'DNS timeout';
      }
    }

    // Set IPv4/IPv6 flags
    result.hasIpv4 = hasIpv4;
    result.hasIpv6 = hasIpv6;

    // Determine NXDOMAIN: only if no CNAME, no A, and no AAAA
    if (!hasCname && aNotFound && aaaaNotFound) {
      result.nxdomain = true;
    }

    // If we have a CNAME, check if the final CNAME target resolves
    if (hasCname && finalCname && !hasIpv4 && !hasIpv6) {
      // Try to resolve the final CNAME target (A and AAAA in parallel)
      const [cnameIpv4Result, cnameIpv6Result] = await Promise.allSettled([
        this.withTimeout(resolve4(finalCname)),
        this.withTimeout(resolve6(finalCname))
      ]);

      const cnameResolved = 
        (cnameIpv4Result.status === 'fulfilled' && cnameIpv4Result.value?.length > 0) ||
        (cnameIpv6Result.status === 'fulfilled' && cnameIpv6Result.value?.length > 0);

      if (!cnameResolved) {
        // CNAME exists but final target doesn't resolve - dangling
        result.nxdomain = true;
      }
    }

    // Run enabled checks in parallel for performance
    const checks: Promise<void>[] = [];
    if (this.checkNs) checks.push(this.checkNsDelegation(subdomain, result));
    if (this.checkMx) checks.push(this.checkMxRecords(subdomain, result));
    if (this.checkSpf) checks.push(this.checkSpfRecords(subdomain, result));
    if (this.checkSrv) checks.push(this.checkSrvRecords(subdomain, result));
    
    if (checks.length > 0) {
      await Promise.all(checks);
    }

    return result;
  }

  /**
   * Check NS delegation for dangling nameservers
   */
  private async checkNsDelegation(subdomain: string, result: DnsResult): Promise<void> {
    try {
      const nsRecords = await this.withTimeout(resolveNs(subdomain));
      if (nsRecords && nsRecords.length > 0) {
        result.nsRecords = nsRecords;
        result.records.push(...nsRecords.map(ns => ({ type: 'NS' as const, value: ns })));
        
        // Check if NS targets resolve (parallel)
        const danglingChecks = await Promise.all(
          nsRecords.map(async (ns) => ({ ns, isDangling: await this.isNsDangling(ns) }))
        );
        const dangling = danglingChecks.filter(c => c.isDangling).map(c => c.ns);
        
        if (dangling.length > 0) {
          result.nsDangling = dangling;
        }
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      // ENODATA means no NS records, which is normal for most subdomains
      if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
        // Other errors we might want to log but not fail
      }
    }
  }

  /**
   * Check if a target resolves (has A or AAAA records) - parallel check
   */
  private async targetResolves(target: string): Promise<boolean> {
    const [ipv4Result, ipv6Result] = await Promise.allSettled([
      this.withTimeout(resolve4(target)),
      this.withTimeout(resolve6(target))
    ]);

    return (
      (ipv4Result.status === 'fulfilled' && ipv4Result.value?.length > 0) ||
      (ipv6Result.status === 'fulfilled' && ipv6Result.value?.length > 0)
    );
  }

  /**
   * Check if a nameserver appears to be dangling (doesn't resolve via A or AAAA)
   */
  async isNsDangling(ns: string): Promise<boolean> {
    return !(await this.targetResolves(ns));
  }

  /**
   * Check MX records for dangling mail servers
   */
  private async checkMxRecords(subdomain: string, result: DnsResult): Promise<void> {
    try {
      const mxRecords = await this.withTimeout(resolveMx(subdomain));
      if (mxRecords && mxRecords.length > 0) {
        result.mxRecords = mxRecords.map(mx => mx.exchange);
        result.records.push(...mxRecords.map(mx => ({ 
          type: 'MX' as const, 
          value: `${mx.priority} ${mx.exchange}` 
        })));
        
        // Check if MX targets resolve (parallel)
        const danglingChecks = await Promise.all(
          mxRecords.map(async (mx) => ({ 
            exchange: mx.exchange, 
            isDangling: await this.isMxDangling(mx.exchange) 
          }))
        );
        const dangling = danglingChecks.filter(c => c.isDangling).map(c => c.exchange);
        
        if (dangling.length > 0) {
          result.mxDangling = dangling;
        }
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      // ENODATA means no MX records, which might be normal
      if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
        // Other errors we might want to log but not fail
      }
    }
  }

  /**
   * Check if a mail server appears to be dangling (doesn't resolve via A or AAAA)
   */
  async isMxDangling(mx: string): Promise<boolean> {
    return !(await this.targetResolves(mx));
  }

  /**
   * Check SPF records for dangling include targets
   */
  private async checkSpfRecords(subdomain: string, result: DnsResult): Promise<void> {
    try {
      const txtRecords = await this.withTimeout(resolveTxt(subdomain));
      if (txtRecords && txtRecords.length > 0) {
        // Find SPF record (may be split across multiple strings)
        for (const record of txtRecords) {
          const joined = record.join('');
          if (joined.startsWith('v=spf1')) {
            result.spfRecord = joined;
            result.records.push({ type: 'TXT' as const, value: joined });
            
            // Extract include directives
            const includeMatches = joined.match(/include:([^\s]+)/g);
            if (includeMatches) {
              result.spfIncludes = includeMatches.map(m => m.replace('include:', ''));
              
              // Check if include targets resolve (parallel)
              const danglingChecks = await Promise.all(
                result.spfIncludes.map(async (include) => ({
                  include,
                  isDangling: await this.isSpfIncludeDangling(include)
                }))
              );
              const dangling = danglingChecks.filter(c => c.isDangling).map(c => c.include);
              
              if (dangling.length > 0) {
                result.spfDangling = dangling;
              }
            }
            break;
          }
        }
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      // ENODATA means no TXT records, which is common
      if (error.code !== 'ENODATA' && error.code !== 'ENOTFOUND') {
        // Other errors we might want to log but not fail
      }
    }
  }

  /**
   * Check if an SPF include target is dangling
   */
  async isSpfIncludeDangling(target: string): Promise<boolean> {
    try {
      // SPF include targets should have TXT records
      const txtRecords = await this.withTimeout(resolveTxt(target));
      return !txtRecords || txtRecords.length === 0;
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      return error.code === 'ENOTFOUND' || error.code === 'ENODATA';
    }
  }

  /**
   * Check common SRV records for dangling targets
   */
  private async checkSrvRecords(subdomain: string, result: DnsResult): Promise<void> {
    // Common SRV record prefixes to check
    const srvPrefixes = [
      '_autodiscover._tcp',  // Microsoft Exchange
      '_sip._tcp',           // SIP/VoIP
      '_sip._tls',           // SIP over TLS
      '_xmpp-client._tcp',   // XMPP/Jabber
      '_xmpp-server._tcp',   // XMPP server-to-server
      '_caldav._tcp',        // CalDAV
      '_carddav._tcp',       // CardDAV
    ];

    const allSrvRecords: string[] = [];
    const targetsToCheck: { prefix: string; target: string }[] = [];

    // Resolve all SRV prefixes in parallel
    const srvResults = await Promise.allSettled(
      srvPrefixes.map(async (prefix) => {
        const srvDomain = `${prefix}.${subdomain}`;
        const records = await this.withTimeout(resolveSrv(srvDomain));
        return { prefix, records };
      })
    );

    // Collect all SRV records and targets
    for (const srvResult of srvResults) {
      if (srvResult.status === 'fulfilled' && srvResult.value.records?.length > 0) {
        const { prefix, records } = srvResult.value;
        for (const srv of records) {
          const target = srv.name;
          allSrvRecords.push(`${prefix}: ${target}`);
          result.records.push({ 
            type: 'SRV', 
            value: `${prefix} ${srv.priority} ${srv.weight} ${srv.port} ${target}` 
          });
          targetsToCheck.push({ prefix, target });
        }
      }
    }

    // Check all targets for dangling in parallel
    if (targetsToCheck.length > 0) {
      const danglingChecks = await Promise.all(
        targetsToCheck.map(async ({ prefix, target }) => ({
          label: `${prefix}: ${target}`,
          isDangling: await this.isSrvTargetDangling(target)
        }))
      );
      const danglingRecords = danglingChecks.filter(c => c.isDangling).map(c => c.label);
      
      if (danglingRecords.length > 0) {
        result.srvDangling = danglingRecords;
      }
    }

    if (allSrvRecords.length > 0) {
      result.srvRecords = allSrvRecords;
    }
  }

  /**
   * Check if an SRV target is dangling (doesn't resolve via A or AAAA)
   */
  async isSrvTargetDangling(target: string): Promise<boolean> {
    // Skip if target is '.' (null target)
    if (target === '.' || target === '') {
      return false;
    }
    return !(await this.targetResolves(target));
  }

  /**
   * Wrap promise with timeout
   */
  private withTimeout<T>(promise: Promise<T>): Promise<T> {
    let timeoutId: NodeJS.Timeout;
    
    const timeoutPromise = new Promise<T>((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error('DNS timeout')), this.timeout);
    });

    return Promise.race([promise, timeoutPromise]).finally(() => {
      clearTimeout(timeoutId);
    });
  }

  /**
   * Normalize domain name (remove trailing dot, trim whitespace)
   */
  private normalizeDomain(domain: string): string {
    let normalized = domain.trim();
    // Remove trailing dot (FQDN format)
    if (normalized.endsWith('.')) {
      normalized = normalized.slice(0, -1);
    }
    return normalized.toLowerCase();
  }

  /**
   * Retry wrapper for DNS operations (for future use)
   */
  async withRetry<T>(fn: () => Promise<T>, retries = 2): Promise<T> {
    let lastError: Error | null = null;
    for (let i = 0; i <= retries; i++) {
      try {
        return await fn();
      } catch (err) {
        lastError = err as Error;
        if (i < retries) {
          // Wait before retry (exponential backoff)
          await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, i)));
        }
      }
    }
    throw lastError;
  }

  /**
   * Check if a CNAME target appears to be dangling (doesn't resolve via A or AAAA)
   */
  async isCnameDangling(cname: string): Promise<boolean> {
    return !(await this.targetResolves(cname));
  }
}

/**
 * Quick DNS check
 */
export async function quickDnsCheck(subdomain: string): Promise<DnsResult> {
  const resolver = new DnsResolver();
  return resolver.resolve(subdomain);
}
