/**
 * Utils Tests - Comprehensive Coverage
 */

import { describe, it, expect } from 'vitest';
import {
  escapeRegex,
  globToRegex,
  chunk,
  parseSubdomains,
  isValidDomain,
  unique,
  withRetry,
  sleep,
  formatRisk,
  formatStatus,
  confidenceToPercent,
  safeJsonParse
} from '../utils.js';

describe('escapeRegex', () => {
  it('should escape special regex characters', () => {
    expect(escapeRegex('test.domain')).toBe('test\\.domain');
    expect(escapeRegex('*.github.io')).toBe('\\*\\.github\\.io');
    expect(escapeRegex('(test)')).toBe('\\(test\\)');
    expect(escapeRegex('[a-z]+')).toBe('\\[a-z\\]\\+');
  });
});

describe('globToRegex', () => {
  it('should convert glob patterns to regex', () => {
    const regex = globToRegex('*.github.io');
    expect(regex.test('test.github.io')).toBe(true);
    expect(regex.test('sub.test.github.io')).toBe(true);
    expect(regex.test('github.io')).toBe(false);
    expect(regex.test('test.github.com')).toBe(false);
  });

  it('should be case insensitive', () => {
    const regex = globToRegex('*.GitHub.IO');
    expect(regex.test('test.github.io')).toBe(true);
    expect(regex.test('TEST.GITHUB.IO')).toBe(true);
  });
});

describe('chunk', () => {
  it('should split array into chunks', () => {
    const arr = [1, 2, 3, 4, 5, 6, 7];
    expect(chunk(arr, 3)).toEqual([[1, 2, 3], [4, 5, 6], [7]]);
    expect(chunk(arr, 2)).toEqual([[1, 2], [3, 4], [5, 6], [7]]);
    expect(chunk(arr, 10)).toEqual([[1, 2, 3, 4, 5, 6, 7]]);
  });

  it('should handle empty array', () => {
    expect(chunk([], 3)).toEqual([]);
  });
});

describe('parseSubdomains', () => {
  it('should parse newline-separated list', () => {
    const input = 'sub1.example.com\nsub2.example.com\nsub3.example.com';
    expect(parseSubdomains(input)).toEqual([
      'sub1.example.com',
      'sub2.example.com',
      'sub3.example.com'
    ]);
  });

  it('should parse comma-separated list', () => {
    const input = 'sub1.example.com,sub2.example.com';
    expect(parseSubdomains(input)).toEqual([
      'sub1.example.com',
      'sub2.example.com'
    ]);
  });

  it('should filter comments and empty lines', () => {
    const input = 'sub1.example.com\n# comment\n\nsub2.example.com';
    expect(parseSubdomains(input)).toEqual([
      'sub1.example.com',
      'sub2.example.com'
    ]);
  });

  it('should lowercase all domains', () => {
    const input = 'SUB1.EXAMPLE.COM\nSub2.Example.Com';
    expect(parseSubdomains(input)).toEqual([
      'sub1.example.com',
      'sub2.example.com'
    ]);
  });
});

describe('isValidDomain', () => {
  it('should validate correct domains', () => {
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('sub.example.com')).toBe(true);
    expect(isValidDomain('sub.sub.example.co.uk')).toBe(true);
  });

  it('should reject invalid domains', () => {
    expect(isValidDomain('example')).toBe(false);
    expect(isValidDomain('-example.com')).toBe(false);
    expect(isValidDomain('example..com')).toBe(false);
  });
});

describe('unique', () => {
  it('should remove duplicates', () => {
    expect(unique([1, 2, 2, 3, 3, 3])).toEqual([1, 2, 3]);
    expect(unique(['a', 'b', 'a', 'c'])).toEqual(['a', 'b', 'c']);
  });

  it('should preserve order', () => {
    expect(unique([3, 1, 2, 1, 3])).toEqual([3, 1, 2]);
  });
});

describe('withRetry', () => {
  it('should succeed on first try', async () => {
    let calls = 0;
    const result = await withRetry(async () => {
      calls++;
      return 'success';
    });
    expect(result).toBe('success');
    expect(calls).toBe(1);
  });

  it('should retry on failure', async () => {
    let calls = 0;
    const result = await withRetry(async () => {
      calls++;
      if (calls < 3) throw new Error('fail');
      return 'success';
    }, { retries: 3, delay: 10 });
    expect(result).toBe('success');
    expect(calls).toBe(3);
  });

  it('should throw after max retries', async () => {
    let calls = 0;
    await expect(withRetry(async () => {
      calls++;
      throw new Error('always fails');
    }, { retries: 2, delay: 10 })).rejects.toThrow('always fails');
    expect(calls).toBe(2);
  });

  it('should call onRetry callback', async () => {
    let retryCount = 0;
    await withRetry(async () => {
      if (retryCount < 1) {
        retryCount++;
        throw new Error('retry');
      }
      return 'done';
    }, { 
      retries: 2, 
      delay: 10,
      onRetry: (attempt) => {
        expect(attempt).toBe(1);
      }
    });
  });
});

describe('sleep', () => {
  it('should wait for specified time', async () => {
    const start = Date.now();
    await sleep(50);
    const elapsed = Date.now() - start;
    expect(elapsed).toBeGreaterThanOrEqual(40);
  });
});

describe('formatRisk', () => {
  it('should format critical risk', () => {
    const result = formatRisk('critical');
    expect(result).toContain('CRITICAL');
  });

  it('should format high risk', () => {
    const result = formatRisk('high');
    expect(result).toContain('HIGH');
  });

  it('should format medium risk', () => {
    const result = formatRisk('medium');
    expect(result).toContain('MEDIUM');
  });

  it('should format low risk', () => {
    const result = formatRisk('low');
    expect(result).toContain('LOW');
  });

  it('should format info risk', () => {
    const result = formatRisk('info');
    expect(result).toContain('INFO');
  });

  it('should handle unknown risk', () => {
    const result = formatRisk('unknown');
    expect(result).toContain('UNKNOWN');
  });
});

describe('formatStatus', () => {
  it('should format vulnerable status', () => {
    const result = formatStatus('vulnerable');
    expect(result).toContain('🔴');
    expect(result).toContain('vulnerable');
  });

  it('should format likely status', () => {
    const result = formatStatus('likely');
    expect(result).toContain('🟠');
  });

  it('should format potential status', () => {
    const result = formatStatus('potential');
    expect(result).toContain('🟡');
  });

  it('should format not_vulnerable status', () => {
    const result = formatStatus('not_vulnerable');
    expect(result).toContain('🟢');
  });

  it('should format unknown status', () => {
    const result = formatStatus('unknown');
    expect(result).toContain('⚪');
  });
});

describe('confidenceToPercent', () => {
  it('should convert 10 to 100%', () => {
    expect(confidenceToPercent(10)).toBe('100%');
  });

  it('should convert 5 to 50%', () => {
    expect(confidenceToPercent(5)).toBe('50%');
  });

  it('should convert 0 to 0%', () => {
    expect(confidenceToPercent(0)).toBe('0%');
  });

  it('should round to nearest percent', () => {
    expect(confidenceToPercent(7)).toBe('70%');
  });
});

describe('safeJsonParse', () => {
  it('should parse valid JSON', () => {
    const result = safeJsonParse('{"key": "value"}', {});
    expect(result).toEqual({ key: 'value' });
  });

  it('should return fallback for invalid JSON', () => {
    const result = safeJsonParse('not json', { default: true });
    expect(result).toEqual({ default: true });
  });

  it('should return fallback for empty string', () => {
    const result = safeJsonParse('', []);
    expect(result).toEqual([]);
  });

  it('should handle arrays', () => {
    const result = safeJsonParse('[1, 2, 3]', []);
    expect(result).toEqual([1, 2, 3]);
  });
});
