/**
 * SubVet - Constants
 * Centralized configuration values and thresholds.
 */

// === DNS ===

/** Default DNS resolution timeout in milliseconds */
export const DNS_TIMEOUT_MS = 5000;

/** Maximum CNAME chain depth to follow */
export const CNAME_CHAIN_MAX_DEPTH = 10;

/** Number of random subdomain probes for wildcard detection */
export const WILDCARD_PROBE_COUNT = 3;

/** Base delay for exponential backoff retries (ms) */
export const RETRY_BASE_DELAY_MS = 100;

/** Default retry count for DNS operations */
export const DEFAULT_RETRY_COUNT = 2;

// === Scanner ===

/** Default scan timeout in milliseconds */
export const SCAN_TIMEOUT_MS = 10000;

/** Default concurrent request limit */
export const DEFAULT_CONCURRENCY = 10;

// === Fingerprint Confidence ===

/** Confidence threshold for "vulnerable" status (high confidence) */
export const CONFIDENCE_VULNERABLE = 7;

/** Default minimum confidence for "likely" status */
export const CONFIDENCE_DEFAULT_MIN = 3;

/** Confidence scale maximum */
export const CONFIDENCE_SCALE = 10;

/** Wildcard partial match confidence reduction */
export const WILDCARD_CONFIDENCE_PENALTY = 2;

// === HTTP ===

/** Maximum body length considered "minimal content" for stale CNAME detection */
export const STALE_CNAME_MAX_BODY_LENGTH = 2000;

// === SRV Prefixes ===

/** Common SRV record prefixes to check for dangling targets */
export const SRV_PREFIXES = [
  '_autodiscover._tcp',  // Microsoft Exchange
  '_sip._tcp',           // SIP/VoIP
  '_sip._tls',           // SIP over TLS
  '_xmpp-client._tcp',   // XMPP/Jabber
  '_xmpp-server._tcp',   // XMPP server-to-server
  '_caldav._tcp',        // CalDAV
  '_carddav._tcp',       // CardDAV
] as const;
