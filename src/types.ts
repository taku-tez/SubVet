/**
 * SubVet - Type Definitions
 */

export type TakeoverStatus = 
  | 'vulnerable'      // Confirmed takeover possible
  | 'likely'          // High probability of takeover
  | 'potential'       // Needs manual verification
  | 'edge_case'       // Edge case, might be vulnerable
  | 'not_vulnerable'  // Service is properly configured
  | 'unknown';        // Could not determine

export type FingerprintMatchType = 
  | 'http_body'       // Match response body content
  | 'http_status'     // Match HTTP status code
  | 'http_header'     // Match response header
  | 'dns_nxdomain'    // NXDOMAIN response
  | 'dns_cname';      // CNAME pattern match

export interface FingerprintRule {
  type: FingerprintMatchType;
  pattern?: string | RegExp;
  value?: number | string;
  header?: string;
}

export interface ServiceFingerprint {
  service: string;
  description: string;
  cnames: string[];          // CNAME patterns (glob-like: *.github.io)
  fingerprints: FingerprintRule[];
  takeoverPossible: boolean;
  documentation?: string;
  poc?: string;              // How to claim/takeover
}

export interface DnsRecord {
  type: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'MX' | 'TXT';
  value: string;
  ttl?: number;
}

export interface DnsResult {
  subdomain: string;
  records: DnsRecord[];
  cname?: string;
  resolved: boolean;
  nxdomain: boolean;
  error?: string;
}

export interface HttpProbeResult {
  url: string;
  status: number | null;
  body: string | null;
  headers: Record<string, string>;
  error?: string;
  responseTime?: number;
}

export interface ScanResult {
  subdomain: string;
  status: TakeoverStatus;
  service: string | null;
  cname: string | null;
  evidence: string[];
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  dns: DnsResult;
  http?: HttpProbeResult;
  poc?: string;
  timestamp: string;
}

export interface ScanSummary {
  total: number;
  vulnerable: number;
  likely: number;
  potential: number;
  safe: number;
  errors: number;
}

export interface ScanOutput {
  version: string;
  timestamp: string;
  target: string;
  options: ScanOptions;
  summary: ScanSummary;
  results: ScanResult[];
}

export interface ScanOptions {
  timeout: number;
  concurrency: number;
  httpProbe: boolean;
  verbose: boolean;
  output?: string;
}

export interface SubdomainSource {
  type: 'file' | 'stdin' | 'ct_logs' | 'dns_brute';
  value?: string;
}
