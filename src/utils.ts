/**
 * SubVet - Utility Functions
 */

/**
 * Escape regex special characters in a string
 */
export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Convert glob pattern to regex
 * e.g., *.github.io -> ^.*\.github\.io$
 */
export function globToRegex(pattern: string): RegExp {
  const regexPattern = pattern
    .replace(/\./g, '\\.')
    .replace(/\*/g, '.*');
  return new RegExp(`^${regexPattern}$`, 'i');
}

/**
 * Retry wrapper for async operations
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: { retries?: number; delay?: number; onRetry?: (attempt: number, error: unknown) => void } = {}
): Promise<T> {
  const { retries = 3, delay = 1000, onRetry } = options;
  
  let lastError: unknown;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        onRetry?.(attempt, error);
        await sleep(delay * attempt);
      }
    }
  }
  throw lastError;
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Chunk array into smaller arrays
 */
export function chunk<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Parse subdomain list from various formats
 */
export function parseSubdomains(input: string): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of input.split(/[\r\n,]+/)) {
    const s = raw.trim().toLowerCase();
    if (s.length > 0 && !s.startsWith('#') && !seen.has(s)) {
      seen.add(s);
      result.push(s);
    }
  }
  return result;
}

/**
 * Validate domain/subdomain format
 */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  for (const label of labels) {
    if (label.length < 1 || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    if (!/^[A-Za-z0-9-]+$/.test(label)) return false;
  }
  // TLD must be alphabetic
  const tld = labels[labels.length - 1];
  if (!/^[A-Za-z]{2,}$/.test(tld)) return false;
  return true;
}

/**
 * Format risk level with color (for terminal output)
 */
export function formatRisk(risk: string): string {
  const colors: Record<string, string> = {
    critical: '\x1b[31m', // red
    high: '\x1b[91m',     // bright red
    medium: '\x1b[33m',   // yellow
    low: '\x1b[32m',      // green
    info: '\x1b[36m'      // cyan
  };
  const reset = '\x1b[0m';
  return `${colors[risk] || ''}${risk.toUpperCase()}${reset}`;
}

/**
 * Format status with emoji
 */
export function formatStatus(status: string): string {
  const emojis: Record<string, string> = {
    vulnerable: '🔴',
    likely: '🟠',
    potential: '🟡',
    not_vulnerable: '🟢',
    unknown: '⚪'
  };
  return `${emojis[status] || '⚪'} ${status}`;
}

/**
 * Calculate confidence percentage
 */
export function confidenceToPercent(confidence: number): string {
  return `${Math.round(confidence * 10)}%`;
}

/**
 * Deduplicate array while preserving order
 */
export function unique<T>(array: T[]): T[] {
  return [...new Set(array)];
}

/**
 * Safe JSON parse with fallback
 */
export function safeJsonParse<T>(str: string, fallback: T): T {
  try {
    return JSON.parse(str) as T;
  } catch {
    return fallback;
  }
}
