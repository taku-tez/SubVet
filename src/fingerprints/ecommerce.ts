/**
 * E-commerce Platform Fingerprints
 */

import type { ServiceFingerprint } from '../types.js';

export const ecommerceFingerprints: ServiceFingerprint[] = [
  {
    service: 'Shopify',
    description: 'Shopify e-commerce',
    cnames: ['*.myshopify.com', 'shops.myshopify.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, this shop is currently unavailable', weight: 10, required: true },
      { type: 'http_body', pattern: 'Only one step left!', weight: 9 },
      { type: 'http_body', pattern: 'shopify', weight: 3 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    negativePatterns: [
      { type: 'http_body', pattern: 'Add to cart', description: 'Active shop' },
      { type: 'http_body', pattern: 'checkout', description: 'Active shop' }
    ],
    takeoverPossible: true,
    poc: 'Create Shopify store and add custom domain'
  },
  {
    service: 'BigCommerce',
    description: 'BigCommerce platform',
    cnames: ['*.bigcommerce.com', '*.mybigcommerce.com'],
    fingerprints: [
      { type: 'http_body', pattern: '<h1>Oops!</h1>', weight: 8 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: false,
    documentation: 'Requires store verification'
  }
];
