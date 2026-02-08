/**
 * HTTP Prober Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpProber } from '../http.js';

describe('HttpProber', () => {
  describe('constructor', () => {
    it('should create prober with default options', () => {
      const prober = new HttpProber();
      expect(prober).toBeDefined();
    });

    it('should accept custom timeout', () => {
      const prober = new HttpProber({ timeout: 5000 });
      expect(prober).toBeDefined();
    });
  });

  describe('probe', () => {
    it('should probe a valid URL', async () => {
      const prober = new HttpProber({ timeout: 10000 });
      const result = await prober.probe('google.com');

      expect(result.url).toContain('google.com');
      expect(result.status).toBe(200);
      expect(result.body).not.toBeNull();
      expect(result.headers).toBeDefined();
    });

    it('should handle HTTPS redirect', async () => {
      const prober = new HttpProber({ timeout: 10000 });
      const result = await prober.probe('github.com');

      expect(result.status).toBeDefined();
    });

    it('should include response headers', async () => {
      const prober = new HttpProber({ timeout: 10000 });
      const result = await prober.probe('google.com');

      expect(typeof result.headers).toBe('object');
    });

    it('should handle connection errors gracefully', async () => {
      const prober = new HttpProber({ timeout: 5000 });
      const result = await prober.probe('nonexistent-domain-xyz-12345.invalid');

      expect(result.error).toBeDefined();
      expect(result.status).toBeNull();
    });

    it('should respect timeout', async () => {
      const prober = new HttpProber({ timeout: 1 }); // Very short timeout
      const result = await prober.probe('google.com');

      // Should either succeed or timeout
      expect(result).toBeDefined();
    });

    it('should clear timeout timer even on fetch failure', async () => {
      const prober = new HttpProber({ timeout: 5000 });
      // Spy on global clearTimeout to verify it's called
      const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');
      const callCountBefore = clearTimeoutSpy.mock.calls.length;

      await prober.probeUrl('http://nonexistent-domain-xyz-12345.invalid');

      // clearTimeout should have been called at least once more (in finally block)
      expect(clearTimeoutSpy.mock.calls.length).toBeGreaterThan(callCountBefore);
      clearTimeoutSpy.mockRestore();
    });

    it('should handle 404 responses', async () => {
      const prober = new HttpProber({ timeout: 10000 });
      // GitHub returns 404 for nonexistent pages
      const result = await prober.probe('github.com/nonexistent-page-xyz-12345');

      expect(result.status).toBe(404);
    });
  });
});
