/**
 * SubVet - Subdomain Takeover Scanner
 * 
 * @example
 * ```typescript
 * import { Scanner, quickScan, listServices } from 'subvet';
 * 
 * // Quick scan
 * const results = await quickScan(['sub.example.com']);
 * 
 * // With options
 * const scanner = new Scanner({ concurrency: 20 });
 * const output = await scanner.scan(['sub1.example.com', 'sub2.example.com']);
 * ```
 */

export { Scanner, quickScan, listServices } from './scanner.js';
export { DnsResolver, quickDnsCheck } from './dns.js';
export { HttpProber, quickHttpProbe } from './http.js';
export { getAllFingerprints, findServiceByCname, getServiceByName } from './fingerprints/index.js';
export { generateReport, generateHtmlReport, generateMarkdownReport, type ReportFormat } from './report.js';
export type {
  ScanResult,
  ScanOutput,
  ScanOptions,
  ScanSummary,
  TakeoverStatus,
  DnsResult,
  DnsRecord,
  HttpProbeResult,
  ServiceFingerprint,
  FingerprintRule,
  FingerprintMatchType
} from './types.js';
