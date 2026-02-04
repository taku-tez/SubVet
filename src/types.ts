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
  | 'dns_cname'       // CNAME pattern match
  | 'ns_nxdomain'     // NS delegation target NXDOMAIN
  | 'mx_nxdomain'     // MX record target NXDOMAIN
  | 'spf_include_nxdomain'  // SPF include target NXDOMAIN
  | 'srv_nxdomain';         // SRV record target NXDOMAIN

export interface FingerprintRule {
  type: FingerprintMatchType;
  pattern?: string | RegExp;
  value?: number | string;
  header?: string;
  required?: boolean;           // If true, this rule MUST match for positive detection
  weight?: number;              // 0-10, higher = more confident (default: 5)
}

export interface NegativePattern {
  type: 'http_body' | 'http_header' | 'http_status';
  pattern?: string | RegExp;
  value?: number | string;
  header?: string;
  description: string;
}

export interface ServiceFingerprint {
  service: string;
  description: string;
  cnames: string[];          // CNAME patterns (glob-like: *.github.io)
  fingerprints: FingerprintRule[];
  negativePatterns?: NegativePattern[];  // Patterns that indicate NOT vulnerable
  minConfidence?: number;    // Minimum confidence score to report (0-10, default: 3)
  takeoverPossible: boolean;
  documentation?: string;
  poc?: string;              // How to claim/takeover
}

export interface DnsRecord {
  type: 'A' | 'AAAA' | 'CNAME' | 'NS' | 'MX' | 'TXT' | 'SRV';
  value: string;
  ttl?: number;
}

export interface DnsResult {
  subdomain: string;
  records: DnsRecord[];
  cname?: string;
  nsRecords?: string[];        // NS delegation targets
  nsDangling?: string[];       // NS targets that don't resolve
  mxRecords?: string[];        // MX record targets
  mxDangling?: string[];       // MX targets that don't resolve
  spfRecord?: string;          // SPF record
  spfIncludes?: string[];      // SPF include targets
  spfDangling?: string[];      // SPF include targets that don't resolve
  srvRecords?: string[];       // SRV record targets
  srvDangling?: string[];      // SRV targets that don't resolve
  hasIpv4: boolean;            // Has A records
  hasIpv6: boolean;            // Has AAAA records
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
  nsCheck: boolean;           // Check NS delegation
  mxCheck: boolean;           // Check MX records
  spfCheck: boolean;          // Check SPF includes
  srvCheck: boolean;          // Check SRV records
  verbose: boolean;
  output?: string;
}

export interface SubdomainSource {
  type: 'file' | 'stdin' | 'ct_logs' | 'dns_brute';
  value?: string;
}
