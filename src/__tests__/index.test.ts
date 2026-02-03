/**
 * Index Module Tests - Exports Verification
 */

import { describe, it, expect } from 'vitest';
import * as SubVet from '../index.js';

describe('SubVet module exports', () => {
  it('should export Scanner class', () => {
    expect(SubVet.Scanner).toBeDefined();
    expect(typeof SubVet.Scanner).toBe('function');
  });

  it('should export quickScan function', () => {
    expect(SubVet.quickScan).toBeDefined();
    expect(typeof SubVet.quickScan).toBe('function');
  });

  it('should export listServices function', () => {
    expect(SubVet.listServices).toBeDefined();
    expect(typeof SubVet.listServices).toBe('function');
  });

  it('should export DnsResolver class', () => {
    expect(SubVet.DnsResolver).toBeDefined();
    expect(typeof SubVet.DnsResolver).toBe('function');
  });

  it('should export fingerprint functions', () => {
    expect(SubVet.findServiceByCname).toBeDefined();
    expect(SubVet.getAllFingerprints).toBeDefined();
    expect(SubVet.getServiceByName).toBeDefined();
  });

  it('should be able to create Scanner instance', () => {
    const scanner = new SubVet.Scanner();
    expect(scanner).toBeDefined();
  });

  it('should be able to list services', () => {
    const services = SubVet.listServices();
    expect(services.length).toBeGreaterThan(0);
  });
});
