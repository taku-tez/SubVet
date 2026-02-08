/**
 * Fingerprints Module Tests - Comprehensive Coverage
 */

import { describe, it, expect } from 'vitest';
import {
  findServiceByCname,
  getAllFingerprints,
  getServiceByName,
  getFingerprintsByCategory,
  listCategories,
  fingerprints,
  cloudFingerprints,
  hostingFingerprints,
  websiteBuilderFingerprints,
  ecommerceFingerprints,
  supportFingerprints,
  marketingFingerprints,
  devtoolsFingerprints,
  miscFingerprints
} from '../fingerprints/index.js';

describe('fingerprints array', () => {
  it('should have fingerprint data', () => {
    expect(fingerprints.length).toBeGreaterThan(50);
  });

  it('should have required fields for each fingerprint', () => {
    for (const fp of fingerprints) {
      expect(fp).toHaveProperty('service');
      expect(fp).toHaveProperty('cnames');
      expect(fp).toHaveProperty('fingerprints');
      expect(fp).toHaveProperty('takeoverPossible');
      expect(fp.cnames.length).toBeGreaterThan(0);
    }
  });

  it('should combine all category fingerprints', () => {
    const totalFromCategories =
      cloudFingerprints.length +
      hostingFingerprints.length +
      websiteBuilderFingerprints.length +
      ecommerceFingerprints.length +
      supportFingerprints.length +
      marketingFingerprints.length +
      devtoolsFingerprints.length +
      miscFingerprints.length;
    expect(fingerprints.length).toBe(totalFromCategories);
  });

  it('should have unique service names', () => {
    const names = fingerprints.map(fp => fp.service);
    const uniqueNames = [...new Set(names)];
    expect(names.length).toBe(uniqueNames.length);
  });
});

describe('findServiceByCname', () => {
  it('should find GitHub Pages by CNAME', () => {
    const result = findServiceByCname('test.github.io');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('GitHub Pages');
  });

  it('should find AWS S3 by CNAME', () => {
    const result = findServiceByCname('bucket.s3.amazonaws.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('AWS S3');
  });

  it('should find AWS S3 with region', () => {
    const result = findServiceByCname('bucket.s3-us-west-2.amazonaws.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('AWS S3');
  });

  it('should find Heroku by CNAME', () => {
    const result = findServiceByCname('myapp.herokuapp.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Heroku');
  });

  it('should find Vercel by CNAME', () => {
    const result = findServiceByCname('myapp.vercel.app');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Vercel');
  });

  it('should find Marketo by CNAME (mktoedge)', () => {
    const result = findServiceByCname('ab62.mktoedge.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Marketo');
  });

  it('should find Marketo by CNAME (mktoweb)', () => {
    const result = findServiceByCname('455-emf-061.mktoweb.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Marketo');
  });

  it('should find Marketo by CNAME (mkto- prefix)', () => {
    const result = findServiceByCname('mkto-ab620141.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Marketo');
  });

  it('should find Short.io by CNAME', () => {
    const result = findServiceByCname('links.short.io');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Short.io');
  });

  it('should find Azure by additional CNAME patterns', () => {
    expect(findServiceByCname('test.azurecr.io')?.service).toBe('Azure');
    expect(findServiceByCname('test.azurehdinsight.net')?.service).toBe('Azure');
    expect(findServiceByCname('test.servicebus.windows.net')?.service).toBe('Azure');
  });

  it('should find Acquia by CNAME', () => {
    const result = findServiceByCname('site.acquia-sites.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Acquia');
  });

  it('should find Frontify by CNAME', () => {
    const result = findServiceByCname('brand.frontify.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Frontify');
  });

  it('should find Mashery by CNAME', () => {
    const result = findServiceByCname('api.mashery.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Mashery');
  });

  it('should find Shopify by CNAME', () => {
    const result = findServiceByCname('shop.myshopify.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Shopify');
  });

  it('should find Zendesk by CNAME', () => {
    const result = findServiceByCname('support.zendesk.com');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Zendesk');
  });

  it('should find CloudFront by CNAME', () => {
    const result = findServiceByCname('d123456.cloudfront.net');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('AWS CloudFront');
  });

  it('should find Azure by CNAME', () => {
    const result = findServiceByCname('myapp.azurewebsites.net');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Azure');
  });

  it('should find Cloudflare Pages', () => {
    const result = findServiceByCname('mysite.pages.dev');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('Cloudflare Pages');
  });

  it('should return null for unknown CNAME', () => {
    const result = findServiceByCname('unknown.example.com');
    expect(result).toBeNull();
  });

  it('should be case insensitive', () => {
    const result = findServiceByCname('TEST.GITHUB.IO');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('GitHub Pages');
  });

  it('should match wildcard patterns correctly', () => {
    expect(findServiceByCname('bucket.s3.amazonaws.com')?.service).toBe('AWS S3');
    expect(findServiceByCname('bucket.s3-us-west-2.amazonaws.com')?.service).toBe('AWS S3');
    expect(findServiceByCname('deep.nested.github.io')?.service).toBe('GitHub Pages');
  });
});

describe('getAllFingerprints', () => {
  it('should return all fingerprints', () => {
    const all = getAllFingerprints();
    expect(all).toEqual(expect.arrayContaining(fingerprints.slice(0, 1)));
    expect(all.length).toBeGreaterThan(0);
  });
});

describe('getServiceByName', () => {
  it('should find service by exact name', () => {
    const result = getServiceByName('GitHub Pages');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('GitHub Pages');
  });

  it('should be case insensitive', () => {
    const result = getServiceByName('github pages');
    expect(result).not.toBeNull();
    expect(result?.service).toBe('GitHub Pages');
  });

  it('should return null for unknown service', () => {
    const result = getServiceByName('Unknown Service');
    expect(result).toBeNull();
  });

  it('should find services from each category', () => {
    expect(getServiceByName('AWS S3')).not.toBeNull();
    expect(getServiceByName('Heroku')).not.toBeNull();
    expect(getServiceByName('Webflow')).not.toBeNull();
    expect(getServiceByName('Shopify')).not.toBeNull();
    expect(getServiceByName('Zendesk')).not.toBeNull();
    expect(getServiceByName('HubSpot')).not.toBeNull();
    expect(getServiceByName('Bitbucket')).not.toBeNull();
  });
});

describe('getFingerprintsByCategory', () => {
  it('should return cloud fingerprints', () => {
    const result = getFingerprintsByCategory('cloud');
    expect(result).toBe(cloudFingerprints);
    expect(result.length).toBeGreaterThan(0);
  });

  it('should return hosting fingerprints', () => {
    const result = getFingerprintsByCategory('hosting');
    expect(result).toBe(hostingFingerprints);
  });

  it('should return website-builders fingerprints', () => {
    const result = getFingerprintsByCategory('website-builders');
    expect(result).toBe(websiteBuilderFingerprints);
  });

  it('should support alias cms for website-builders', () => {
    const result = getFingerprintsByCategory('cms');
    expect(result).toBe(websiteBuilderFingerprints);
  });

  it('should return ecommerce fingerprints', () => {
    const result = getFingerprintsByCategory('ecommerce');
    expect(result).toBe(ecommerceFingerprints);
  });

  it('should return support fingerprints', () => {
    const result = getFingerprintsByCategory('support');
    expect(result).toBe(supportFingerprints);
  });

  it('should support alias helpdesk for support', () => {
    const result = getFingerprintsByCategory('helpdesk');
    expect(result).toBe(supportFingerprints);
  });

  it('should return marketing fingerprints', () => {
    const result = getFingerprintsByCategory('marketing');
    expect(result).toBe(marketingFingerprints);
  });

  it('should return devtools fingerprints', () => {
    const result = getFingerprintsByCategory('devtools');
    expect(result).toBe(devtoolsFingerprints);
  });

  it('should support alias developer for devtools', () => {
    const result = getFingerprintsByCategory('developer');
    expect(result).toBe(devtoolsFingerprints);
  });

  it('should return misc fingerprints', () => {
    const result = getFingerprintsByCategory('misc');
    expect(result).toBe(miscFingerprints);
  });

  it('should return empty array for unknown category', () => {
    const result = getFingerprintsByCategory('unknown');
    expect(result).toEqual([]);
  });
});

describe('listCategories', () => {
  it('should return all categories with counts', () => {
    const categories = listCategories();
    expect(categories.length).toBe(8);

    const names = categories.map(c => c.name);
    expect(names).toContain('cloud');
    expect(names).toContain('hosting');
    expect(names).toContain('website-builders');
    expect(names).toContain('ecommerce');
    expect(names).toContain('support');
    expect(names).toContain('marketing');
    expect(names).toContain('devtools');
    expect(names).toContain('misc');
  });

  it('should have correct counts', () => {
    const categories = listCategories();
    const cloudCat = categories.find(c => c.name === 'cloud');
    expect(cloudCat?.count).toBe(cloudFingerprints.length);
  });

  it('should sum to total fingerprints', () => {
    const categories = listCategories();
    const totalCount = categories.reduce((sum, c) => sum + c.count, 0);
    expect(totalCount).toBe(fingerprints.length);
  });
});

describe('glob pattern matching', () => {
  it('should match * wildcard correctly', () => {
    // *.github.io should match anything.github.io
    expect(findServiceByCname('test.github.io')?.service).toBe('GitHub Pages');
    expect(findServiceByCname('deep.nested.github.io')?.service).toBe('GitHub Pages');
  });

  it('should handle special regex characters in patterns', () => {
    // Patterns with dots should work correctly
    expect(findServiceByCname('bucket.s3.amazonaws.com')?.service).toBe('AWS S3');
    expect(findServiceByCname('app.herokuapp.com')?.service).toBe('Heroku');
  });

  it('should handle multiple wildcards', () => {
    // *.s3-*.amazonaws.com
    expect(findServiceByCname('bucket.s3-us-west-2.amazonaws.com')?.service).toBe('AWS S3');
  });

  it('should handle trailing dot in CNAME (FQDN format)', () => {
    // Some DNS resolvers return FQDNs with trailing dots
    expect(findServiceByCname('test.github.io.')?.service).toBe('GitHub Pages');
    expect(findServiceByCname('bucket.s3.amazonaws.com.')?.service).toBe('AWS S3');
  });

  it('should handle whitespace in CNAME', () => {
    expect(findServiceByCname('  test.github.io  ')?.service).toBe('GitHub Pages');
  });

  it('should be case insensitive', () => {
    expect(findServiceByCname('TEST.GITHUB.IO')?.service).toBe('GitHub Pages');
    expect(findServiceByCname('Bucket.S3.AmazonAWS.COM')?.service).toBe('AWS S3');
  });
});

describe('fingerprint data quality', () => {
  it('should have valid CNAME patterns', () => {
    for (const fp of fingerprints) {
      for (const cname of fp.cnames) {
        expect(cname).toContain('.');
        expect(cname).not.toContain('..');
      }
    }
  });

  it('should have fingerprint rules for takeover-possible services', () => {
    const takeoverServices = fingerprints.filter(fp => fp.takeoverPossible);
    for (const fp of takeoverServices) {
      expect(fp.fingerprints.length).toBeGreaterThan(0);
    }
  });

  it('should have poc for takeover-possible services', () => {
    const takeoverServices = fingerprints.filter(fp => fp.takeoverPossible);
    for (const fp of takeoverServices) {
      expect(fp.poc).toBeDefined();
      expect(fp.poc?.length).toBeGreaterThan(0);
    }
  });

  it('should have descriptions for all services', () => {
    for (const fp of fingerprints) {
      expect(fp.description).toBeDefined();
      expect(fp.description.length).toBeGreaterThan(0);
    }
  });
});
