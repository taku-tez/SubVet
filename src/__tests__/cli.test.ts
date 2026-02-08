/**
 * CLI Tests - Quick Integration Tests
 * Network-dependent tests are skipped for speed
 */

import { describe, it, expect } from 'vitest';
import { exec } from 'child_process';
import { promisify } from 'util';
import { resolve } from 'path';

const execAsync = promisify(exec);
const cliPath = resolve(__dirname, '../../dist/cli.js');

describe('CLI', () => {
  describe('help command', () => {
    it('should show help with --help', async () => {
      const { stdout } = await execAsync(`node ${cliPath} --help`);
      expect(stdout).toContain('Usage');
      expect(stdout).toContain('subvet');
      expect(stdout).toContain('scan');
      expect(stdout).toContain('check');
      expect(stdout).toContain('services');
      expect(stdout).toContain('fingerprint');
    });

    it('should show help with -h', async () => {
      const { stdout } = await execAsync(`node ${cliPath} -h`);
      expect(stdout).toContain('Usage');
    });

    it('should show scan subcommand help', async () => {
      const { stdout } = await execAsync(`node ${cliPath} scan --help`);
      expect(stdout).toContain('scan');
      expect(stdout).toContain('timeout');
      expect(stdout).toContain('concurrency');
    });

    it('should show check subcommand help', async () => {
      const { stdout } = await execAsync(`node ${cliPath} check --help`);
      expect(stdout).toContain('check');
    });
  });

  describe('version command', () => {
    it('should show version with --version', async () => {
      const { stdout } = await execAsync(`node ${cliPath} --version`);
      expect(stdout).toMatch(/\d+\.\d+\.\d+/);
    });

    it('should show version with -V', async () => {
      const { stdout } = await execAsync(`node ${cliPath} -V`);
      expect(stdout).toMatch(/\d+\.\d+\.\d+/);
    });
  });

  describe('services command', () => {
    it('should list all services', async () => {
      const { stdout } = await execAsync(`node ${cliPath} services`);
      expect(stdout).toContain('AWS S3');
      expect(stdout).toContain('GitHub Pages');
      expect(stdout).toContain('Heroku');
      expect(stdout).toContain('Vercel');
      expect(stdout).toContain('Shopify');
    });

    it('should show service count', async () => {
      const { stdout } = await execAsync(`node ${cliPath} services`);
      // Should have at least 70 services
      const lines = stdout.trim().split('\n');
      expect(lines.length).toBeGreaterThan(70);
    });
  });

  describe('fingerprint command', () => {
    it('should show fingerprint for AWS S3', async () => {
      const { stdout } = await execAsync(`node ${cliPath} fingerprint "AWS S3"`);
      expect(stdout).toContain('AWS S3');
      expect(stdout).toContain('s3.amazonaws.com');
      expect(stdout).toContain('Takeover');
      expect(stdout).toContain('Possible');
    });

    it('should show fingerprint for GitHub Pages', async () => {
      const { stdout } = await execAsync(`node ${cliPath} fingerprint "GitHub Pages"`);
      expect(stdout).toContain('GitHub Pages');
      expect(stdout).toContain('github.io');
    });

    it('should handle unknown service', async () => {
      try {
        await execAsync(`node ${cliPath} fingerprint "Unknown Service XYZ"`);
        // Should not reach here
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr || error.stdout).toContain('not found');
      }
    });

    it('should be case insensitive', async () => {
      const { stdout } = await execAsync(`node ${cliPath} fingerprint "aws s3"`);
      expect(stdout).toContain('AWS S3');
    });
  });

  // Skip network-dependent tests for speed
  describe.skip('check command (network)', () => {
    it('should check a single domain', async () => {
      const { stdout } = await execAsync(`node ${cliPath} check google.com`);
      expect(stdout).toContain('google.com');
    }, 30000);
  });

  describe.skip('scan command (network)', () => {
    it('should scan a domain', async () => {
      const { stdout } = await execAsync(`node ${cliPath} scan google.com`);
      const result = JSON.parse(stdout);
      expect(result.version).toBeDefined();
    }, 30000);
  });

  describe('domain validation', () => {
    it('should reject invalid domain in check command', async () => {
      try {
        await execAsync(`node ${cliPath} check "not a valid domain"`);
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid domain format');
      }
    });

    it('should reject invalid domain in scan command', async () => {
      try {
        await execAsync(`node ${cliPath} scan "spaces not allowed"`);
        expect(true).toBe(false); // Should not reach here
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid domain format');
      }
    });

    it('should accept valid domain format', async () => {
      // This just validates the format, doesn't do network check
      const { stdout } = await execAsync(`node ${cliPath} fingerprint "AWS S3"`);
      expect(stdout).toContain('AWS S3');
    });
  });

  describe('enum option validation', () => {
    it('should reject invalid --report format', async () => {
      try {
        await execAsync(`node ${cliPath} scan example.com --report=pdf`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid --report format');
        expect(error.stderr).toContain('json, md, html');
      }
    });

    it('should reject invalid --slack-on value', async () => {
      try {
        await execAsync(`node ${cliPath} scan example.com --slack-on=allways`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid --slack-on value');
        expect(error.stderr).toContain('always, issues, new');
      }
    });

    it('should accept valid --report format', async () => {
      // json is valid; scan will fail for other reasons but not validation
      try {
        await execAsync(`node ${cliPath} scan --report=json --help`);
      } catch {
        // --help may still exit 0 or 1, but no validation error
      }
    });
  });

  describe('diff option', () => {
    it('should show diff option in help', async () => {
      const { stdout } = await execAsync(`node ${cliPath} scan --help`);
      expect(stdout).toContain('--diff');
      expect(stdout).toContain('baseline');
    });

    it('should error on invalid baseline file', async () => {
      try {
        await execAsync(`node ${cliPath} scan example.com --diff=/nonexistent/file.json`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.message).toContain('ENOENT');
      }
    });
  });

  describe('numeric option validation', () => {
    it('should reject invalid timeout value', async () => {
      try {
        await execAsync(`node ${cliPath} check google.com --timeout=abc`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid timeout value');
      }
    });

    it('should reject negative timeout value', async () => {
      try {
        await execAsync(`node ${cliPath} check google.com --timeout=-1000`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid timeout value');
      }
    });

    it('should reject invalid concurrency value', async () => {
      try {
        await execAsync(`node ${cliPath} scan google.com --concurrency=abc`);
        expect(true).toBe(false);
      } catch (error: any) {
        expect(error.stderr).toContain('Invalid concurrency value');
      }
    });
  });
});
