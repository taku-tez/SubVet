/**
 * SubVet - HTTP Probe Module
 */

import type { HttpProbeResult } from './types.js';
import { VERSION } from './version.js';

export interface HttpProbeOptions {
  timeout?: number;
  followRedirects?: boolean;
  maxBodySize?: number;
  userAgent?: string;
}

const DEFAULT_OPTIONS: Required<HttpProbeOptions> = {
  timeout: 10000,
  followRedirects: true,
  maxBodySize: 1024 * 100, // 100KB
  userAgent: `SubVet/${VERSION} (Subdomain Takeover Scanner)`
};

export class HttpProber {
  private options: Required<HttpProbeOptions>;

  constructor(options: HttpProbeOptions = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }

  /**
   * Probe a subdomain via HTTP/HTTPS
   */
  async probe(subdomain: string): Promise<HttpProbeResult> {
    // Try HTTPS first, then HTTP
    const httpsResult = await this.probeUrl(`https://${subdomain}`);
    if (httpsResult.status !== null) {
      return httpsResult;
    }

    // Fall back to HTTP
    const httpResult = await this.probeUrl(`http://${subdomain}`);
    return httpResult;
  }

  /**
   * Probe a specific URL
   */
  async probeUrl(url: string): Promise<HttpProbeResult> {
    const startTime = Date.now();
    const result: HttpProbeResult = {
      url,
      status: null,
      body: null,
      headers: {}
    };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.options.timeout);

      const response = await fetch(url, {
        method: 'GET',
        redirect: this.options.followRedirects ? 'follow' : 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': this.options.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
        }
      });

      clearTimeout(timeoutId);

      result.status = response.status;
      result.responseTime = Date.now() - startTime;

      // Collect headers
      response.headers.forEach((value, key) => {
        result.headers[key.toLowerCase()] = value;
      });

      // Get body (limited size) - efficient concatenation
      try {
        const reader = response.body?.getReader();
        if (reader) {
          const chunks: Uint8Array[] = [];
          let totalSize = 0;

          while (totalSize < this.options.maxBodySize) {
            const { done, value } = await reader.read();
            if (done) break;
            
            chunks.push(value);
            totalSize += value.length;
            
            // Stop early if we've exceeded max size
            if (totalSize >= this.options.maxBodySize) {
              reader.cancel();
              break;
            }
          }

          // Efficient concatenation using Buffer.concat (or manual for Uint8Array)
          const totalLength = Math.min(totalSize, this.options.maxBodySize);
          const combined = new Uint8Array(totalLength);
          let offset = 0;
          for (const chunk of chunks) {
            const bytesToCopy = Math.min(chunk.length, totalLength - offset);
            combined.set(chunk.subarray(0, bytesToCopy), offset);
            offset += bytesToCopy;
            if (offset >= totalLength) break;
          }

          const decoder = new TextDecoder('utf-8', { fatal: false });
          result.body = decoder.decode(combined);
        }
      } catch {
        // Body read error, might be binary or too large
      }

    } catch (err) {
      const error = err as Error;
      result.error = error.message;
      
      if (error.name === 'AbortError') {
        result.error = 'Request timeout';
      } else if (error.message.includes('ECONNREFUSED')) {
        result.error = 'Connection refused';
      } else if (error.message.includes('ENOTFOUND')) {
        result.error = 'DNS resolution failed';
      } else if (error.message.includes('certificate')) {
        result.error = 'SSL certificate error';
      }
    }

    return result;
  }
}

/**
 * Quick HTTP probe
 */
export async function quickHttpProbe(subdomain: string): Promise<HttpProbeResult> {
  const prober = new HttpProber();
  return prober.probe(subdomain);
}
