/**
 * SubVet - DNS Resolution Module
 */

import dns from 'node:dns';
import { promisify } from 'node:util';
import type { DnsResult } from './types.js';

const resolveCname = promisify(dns.resolveCname);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

export interface DnsResolverOptions {
  timeout?: number;
}

export class DnsResolver {
  private timeout: number;

  constructor(options: DnsResolverOptions = {}) {
    this.timeout = options.timeout ?? 5000;
  }

  /**
   * Resolve DNS records for a subdomain
   */
  async resolve(subdomain: string): Promise<DnsResult> {
    const result: DnsResult = {
      subdomain,
      records: [],
      resolved: false,
      nxdomain: false
    };

    // Try CNAME first
    try {
      const cnames = await this.withTimeout(resolveCname(subdomain));
      if (cnames && cnames.length > 0) {
        result.cname = cnames[0];
        result.records.push({ type: 'CNAME', value: cnames[0] });
        result.resolved = true;

        // Follow CNAME chain
        let currentCname = cnames[0];
        let chainDepth = 0;
        while (chainDepth < 10) {
          try {
            const nextCnames = await this.withTimeout(resolveCname(currentCname));
            if (nextCnames && nextCnames.length > 0) {
              currentCname = nextCnames[0];
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
        result.cname = currentCname;
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        // No CNAME, that's fine, try A/AAAA
      } else if (error.code === 'SERVFAIL' || error.code === 'ESERVFAIL') {
        result.error = 'DNS server failure';
      }
    }

    // Try A records
    try {
      const ipv4 = await this.withTimeout(resolve4(subdomain));
      if (ipv4 && ipv4.length > 0) {
        for (const ip of ipv4) {
          result.records.push({ type: 'A', value: ip });
        }
        result.resolved = true;
      }
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      if (error.code === 'ENOTFOUND') {
        if (!result.resolved) {
          result.nxdomain = true;
        }
      }
    }

    // Try AAAA records
    try {
      const ipv6 = await this.withTimeout(resolve6(subdomain));
      if (ipv6 && ipv6.length > 0) {
        for (const ip of ipv6) {
          result.records.push({ type: 'AAAA', value: ip });
        }
        result.resolved = true;
      }
    } catch {
      // AAAA failure is common, ignore
    }

    // If we got a CNAME but no A/AAAA, that's suspicious
    if (result.cname && result.records.filter(r => r.type === 'A' || r.type === 'AAAA').length === 0) {
      // CNAME exists but doesn't resolve - potential dangling
      result.nxdomain = true;
    }

    return result;
  }

  /**
   * Wrap promise with timeout
   */
  private withTimeout<T>(promise: Promise<T>): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => 
        setTimeout(() => reject(new Error('DNS timeout')), this.timeout)
      )
    ]);
  }

  /**
   * Check if a CNAME target appears to be dangling
   */
  async isCnameDangling(cname: string): Promise<boolean> {
    try {
      const ipv4 = await this.withTimeout(resolve4(cname));
      return !ipv4 || ipv4.length === 0;
    } catch (err) {
      const error = err as NodeJS.ErrnoException;
      return error.code === 'ENOTFOUND' || error.code === 'ENODATA';
    }
  }
}

/**
 * Quick DNS check
 */
export async function quickDnsCheck(subdomain: string): Promise<DnsResult> {
  const resolver = new DnsResolver();
  return resolver.resolve(subdomain);
}
