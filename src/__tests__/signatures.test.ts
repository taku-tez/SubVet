import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadSignaturesFromDir, getBuiltinSignaturesDir } from '../signatures.js';

const testDir = join(tmpdir(), `subvet-sig-test-${Date.now()}`);

beforeAll(() => {
  mkdirSync(testDir, { recursive: true });
});

afterAll(() => {
  rmSync(testDir, { recursive: true, force: true });
});

describe('loadSignaturesFromDir', () => {
  it('should return empty array for non-existent dir', () => {
    const result = loadSignaturesFromDir('/nonexistent/path');
    expect(result).toEqual([]);
  });

  it('should load valid YAML signatures', () => {
    const yaml = `
- service: "Test Service"
  description: "A test service"
  cnames:
    - "*.test.example.com"
  fingerprints:
    - type: "http_body"
      pattern: "Not Found"
      weight: 10
      required: true
  takeoverPossible: true
  poc: "Create test account"
`;
    writeFileSync(join(testDir, 'test.yaml'), yaml);
    const result = loadSignaturesFromDir(testDir);
    expect(result).toHaveLength(1);
    expect(result[0].service).toBe('Test Service');
    expect(result[0].cnames).toEqual(['*.test.example.com']);
    expect(result[0].fingerprints[0].type).toBe('http_body');
    expect(result[0].fingerprints[0].required).toBe(true);
    expect(result[0].takeoverPossible).toBe(true);
  });

  it('should load negative patterns', () => {
    const yaml = `
- service: "Neg Test"
  description: "Test negative patterns"
  cnames:
    - "*.neg.example.com"
  fingerprints:
    - type: "http_body"
      pattern: "error"
      weight: 10
  negativePatterns:
    - type: "http_body"
      pattern: "active"
      description: "Service is active"
  takeoverPossible: false
`;
    writeFileSync(join(testDir, 'neg.yaml'), yaml);
    const result = loadSignaturesFromDir(testDir);
    const neg = result.find(s => s.service === 'Neg Test');
    expect(neg).toBeDefined();
    expect(neg!.negativePatterns).toHaveLength(1);
    expect(neg!.negativePatterns![0].description).toBe('Service is active');
  });

  it('should ignore non-yaml files', () => {
    writeFileSync(join(testDir, 'readme.txt'), 'not yaml');
    const result = loadSignaturesFromDir(testDir);
    // Should only have entries from .yaml files
    expect(result.every(s => s.service !== undefined)).toBe(true);
  });
});

describe('getBuiltinSignaturesDir', () => {
  it('should return a valid path', () => {
    const dir = getBuiltinSignaturesDir();
    expect(dir).toContain('signatures');
  });
});

describe('built-in YAML signatures', () => {
  it('should load all 88 built-in signatures', () => {
    const dir = getBuiltinSignaturesDir();
    const sigs = loadSignaturesFromDir(dir);
    expect(sigs.length).toBe(88);
  });

  it('should include AWS S3', () => {
    const dir = getBuiltinSignaturesDir();
    const sigs = loadSignaturesFromDir(dir);
    const s3 = sigs.find(s => s.service === 'AWS S3');
    expect(s3).toBeDefined();
    expect(s3!.takeoverPossible).toBe(true);
  });
});

describe('custom signatures directory', () => {
  it('should load custom signatures that override built-in', () => {
    const customDir = join(testDir, 'custom');
    mkdirSync(customDir, { recursive: true });
    const yaml = `
- service: "Custom Service"
  description: "My custom check"
  cnames:
    - "*.custom.example.com"
  fingerprints:
    - type: "http_body"
      pattern: "custom error"
      weight: 10
  takeoverPossible: true
`;
    writeFileSync(join(customDir, 'custom.yaml'), yaml);
    const result = loadSignaturesFromDir(customDir);
    expect(result.some(s => s.service === 'Custom Service')).toBe(true);
  });
});
