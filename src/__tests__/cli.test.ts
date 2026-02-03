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
});
