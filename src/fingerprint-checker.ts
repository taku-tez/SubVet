/**
 * SubVet - Fingerprint Checker
 * HTTP/DNS fingerprint matching and generic pattern detection.
 */

import type { FingerprintRule, ServiceFingerprint } from './types.js';
import { escapeRegex } from './utils.js';
import { STALE_CNAME_MAX_BODY_LENGTH } from './constants.js';

/** Result of HTTP fingerprint checking */
export interface FingerprintCheckResult {
  matches: string[];
  confidence: number;
  requiredMet: boolean;
  negativeMatch: boolean;
}

/** HTTP response data needed for fingerprint checks */
export interface HttpResponseData {
  status: number | null;
  body: string | null;
  headers: Record<string, string>;
}

/**
 * Check fingerprint rules against HTTP response.
 * Returns { matches, confidence, requiredMet, negativeMatch }
 * - confidence: 0-10 score based on matched rules
 * - requiredMet: true if all required rules matched
 */
export function checkFingerprints(
  service: ServiceFingerprint,
  http: HttpResponseData
): FingerprintCheckResult {
  const matches: string[] = [];
  let totalWeight = 0;
  let matchedWeight = 0;
  const requiredRules: { rule: FingerprintRule; matched: boolean }[] = [];

  // Only evaluate HTTP-phase rules for totalWeight/requiredRules calculation.
  // DNS rules (dns_nxdomain, dns_cname, etc.) are evaluated in checkDnsFingerprints()
  // and should not dilute the HTTP confidence score.
  const httpRuleTypes = new Set(['http_body', 'http_status', 'http_header']);

  // Check positive patterns
  for (const rule of service.fingerprints) {
    // Skip non-HTTP rules — they don't belong in HTTP confidence scoring
    if (!httpRuleTypes.has(rule.type)) {
      continue;
    }

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
 * Check DNS fingerprint rules (dns_nxdomain, dns_cname, ns_nxdomain, etc.)
 */
export function checkDnsFingerprints(
  service: ServiceFingerprint,
  dns: {
    nxdomain: boolean;
    cname?: string;
    nsDangling?: string[];
    mxDangling?: string[];
    spfDangling?: string[];
    srvDangling?: string[];
    txtDangling?: string[];
  },
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

      case 'ns_nxdomain':
        if (dns.nsDangling && dns.nsDangling.length > 0) {
          matches.push(`DNS: Dangling NS delegation (${dns.nsDangling.join(', ')})`);
        }
        break;

      case 'mx_nxdomain':
        if (dns.mxDangling && dns.mxDangling.length > 0) {
          matches.push(`DNS: Dangling MX record (${dns.mxDangling.join(', ')})`);
        }
        break;

      case 'spf_include_nxdomain':
        if (dns.spfDangling && dns.spfDangling.length > 0) {
          matches.push(`DNS: Dangling SPF include (${dns.spfDangling.join(', ')})`);
        }
        break;

      case 'srv_nxdomain':
        if (dns.srvDangling && dns.srvDangling.length > 0) {
          matches.push(`DNS: Dangling SRV record (${dns.srvDangling.join(', ')})`);
        }
        break;

      case 'txt_ref_nxdomain':
        if (dns.txtDangling && dns.txtDangling.length > 0) {
          matches.push(`DNS: Dangling TXT domain reference (${dns.txtDangling.join(', ')})`);
        }
        break;
    }
  }

  return matches;
}

/**
 * Check generic patterns that might indicate takeover.
 * Now with stronger compound matching.
 */
export function checkGenericPatterns(body: string, status: number | null): string[] {
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
 * Check for stale CNAME records pointing to SaaS services no longer in use.
 * Generic detection that works across unknown services.
 */
export function checkStaleCname(
  cname: string | null,
  http: { status: number | null; body: string | null; headers: Record<string, string> },
  _nxdomain: boolean
): string[] {
  if (!cname) return [];
  const checks: string[] = [];

  // Pattern 2: Redirect to SaaS login/default page
  const location = http.headers['location'] ?? '';
  const saasLoginRedirects = [
    { pattern: /marketo\.com/i, name: 'Marketo' },
    { pattern: /salesforce\.com/i, name: 'Salesforce' },
    { pattern: /pardot\.com/i, name: 'Pardot' },
    { pattern: /hubspot\.com/i, name: 'HubSpot' },
    { pattern: /zendesk\.com\/auth/i, name: 'Zendesk' },
    { pattern: /freshdesk\.com\/login/i, name: 'Freshdesk' },
    { pattern: /intercom\.com/i, name: 'Intercom' },
    { pattern: /mailchimp\.com/i, name: 'Mailchimp' },
    { pattern: /sendgrid\.(com|net)/i, name: 'SendGrid' },
  ];

  for (const { pattern, name } of saasLoginRedirects) {
    if (pattern.test(location)) {
      checks.push(`Stale CNAME: Redirects to ${name} login/default page`);
      return checks;
    }
  }

  // Pattern 3: SaaS default/error pages served (not customer content)
  if (http.body) {
    const saasDefaultPages = [
      { pattern: /Login \| Marketo/i, name: 'Marketo' },
      { pattern: /Pardot\s*·?\s*Login/i, name: 'Pardot' },
      { pattern: /There isn't a .* page here/i, name: 'HubSpot' },
      { pattern: /Domain not found.*hubspot/i, name: 'HubSpot' },
      { pattern: /This UserVoice subdomain is currently available/i, name: 'UserVoice' },
      { pattern: /Help Center Closed/i, name: 'Zendesk' },
      { pattern: /project not found/i, name: 'Unknown SaaS' },
      { pattern: /This page is reserved for/i, name: 'Unknown SaaS' },
      { pattern: /is not a registered namespace/i, name: 'Unknown SaaS' },
    ];

    for (const { pattern, name } of saasDefaultPages) {
      if (pattern.test(http.body)) {
        checks.push(`Stale CNAME: ${name} default/error page detected`);
        return checks;
      }
    }

    // Pattern 4: CNAME to known SaaS domain but response is a generic error
    const knownSaasDomains = [
      /\.cloudfront\.net$/i,
      /\.herokuapp\.com$/i,
      /\.azurewebsites\.net$/i,
      /\.trafficmanager\.net$/i,
      /\.cloudapp\.azure\.com$/i,
      /\.ghost\.io$/i,
      /\.wordpress\.com$/i,
      /\.shopify\.com$/i,
      /\.myshopify\.com$/i,
      /\.squarespace\.com$/i,
      /\.webflow\.io$/i,
      /\.netlify\.app$/i,
      /\.vercel\.app$/i,
      /\.firebaseapp\.com$/i,
      /\.zendesk\.com$/i,
      /\.freshdesk\.com$/i,
      /\.intercom\.io$/i,
      /\.statuspage\.io$/i,
      /\.mktoedge\.com$/i,
      /\.mktoweb\.com$/i,
      /\.pardot\.com$/i,
      /\.hubspot\.net$/i,
      /\.hs-sites\.com$/i,
      /\.sendgrid\.net$/i,
    ];

    const isKnownSaas = knownSaasDomains.some(p => p.test(cname));
    if (isKnownSaas && http.status !== null) {
      // CNAME to known SaaS + error status = likely stale
      if (http.status === 404 || http.status === 403 || http.status === 410) {
        const bodyLen = (http.body ?? '').length;
        const hasMinimalContent = bodyLen < STALE_CNAME_MAX_BODY_LENGTH;
        if (hasMinimalContent) {
          checks.push(`Stale CNAME: ${cname} returns ${http.status} with minimal content`);
        }
      }
      // Redirect to SaaS root (not a specific page) = not configured
      if ((http.status === 301 || http.status === 302) && location) {
        const redirectsToSaasRoot = /^https?:\/\/[^/]+\/?$/.test(location) || 
                                     /login|signin|auth/i.test(location);
        if (redirectsToSaasRoot) {
          checks.push(`Stale CNAME: ${cname} redirects to SaaS root/login (${http.status})`);
        }
      }
    }
  }

  return checks;
}
