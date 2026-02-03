/**
 * Marketing & Landing Page Platform Fingerprints
 */

import type { ServiceFingerprint } from '../types.js';

export const marketingFingerprints: ServiceFingerprint[] = [
  {
    service: 'Unbounce',
    description: 'Unbounce landing pages',
    cnames: ['*.unbouncepages.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'The requested URL was not found on this server', weight: 6 },
      { type: 'http_body', pattern: 'The page you were looking for doesn\'t exist', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Add custom domain in Unbounce settings'
  },
  {
    service: 'HubSpot',
    description: 'HubSpot CMS',
    cnames: ['*.hubspot.net', '*.hs-sites.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Domain not found', weight: 10 },
      { type: 'http_status', value: 404, weight: 2 }
    ],
    takeoverPossible: false,
    documentation: 'Requires HubSpot account verification'
  },
  {
    service: 'Campaign Monitor',
    description: 'Campaign Monitor landing pages',
    cnames: ['*.createsend.com', '*.campaignmonitor.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Trying to access your account?', weight: 10, required: true }
    ],
    takeoverPossible: true,
    documentation: 'https://help.campaignmonitor.com/custom-domain-names',
    poc: 'Create Campaign Monitor page and add custom domain'
  },
  {
    service: 'GetResponse',
    description: 'GetResponse landing pages',
    cnames: ['*.getresponse.com', '*.gr8.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'With GetResponse Landing Pages, lead generation has never been easier', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create GetResponse landing page with custom domain'
  },
  {
    service: 'LaunchRock',
    description: 'LaunchRock landing pages',
    cnames: ['*.launchrock.com'],
    fingerprints: [
      { type: 'http_body', pattern: "It looks like you may have taken a wrong turn somewhere", weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create LaunchRock page with custom domain'
  },
  {
    service: 'Landingi',
    description: 'Landingi landing pages',
    cnames: ['*.landingi.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'It looks like you\'re lost', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create landing page with custom domain'
  },
  {
    service: 'Agile CRM',
    description: 'Agile CRM landing pages',
    cnames: ['*.agilecrm.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, this page is no longer available', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Create landing page in Agile CRM'
  },
  {
    service: 'Uberflip',
    description: 'Uberflip content hub',
    cnames: ['*.read.uberflip.com', '*.uberflip.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'The URL you\'ve accessed does not provide a hub', weight: 10, required: true },
      { type: 'http_body', pattern: 'does not provide a hub', weight: 8 }
    ],
    takeoverPossible: true,
    documentation: 'https://help.uberflip.com/hc/en-us/articles/360018786372',
    poc: 'Create Uberflip hub and configure custom domain'
  },
  {
    service: 'Smartling',
    description: 'Smartling translation',
    cnames: ['*.smartling.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Domain is not configured', weight: 10, required: true }
    ],
    takeoverPossible: true,
    poc: 'Contact Smartling support to claim'
  }
];
