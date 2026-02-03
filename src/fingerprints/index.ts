/**
 * SubVet - Fingerprint Database
 * Based on: https://github.com/EdOverflow/can-i-take-over-xyz
 */

import type { ServiceFingerprint } from '../types.js';

export const fingerprints: ServiceFingerprint[] = [
  // === Cloud Platforms ===
  {
    service: 'AWS S3',
    description: 'Amazon S3 bucket',
    cnames: ['*.s3.amazonaws.com', '*.s3-*.amazonaws.com', '*.s3.*.amazonaws.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'NoSuchBucket' },
      { type: 'http_body', pattern: 'The specified bucket does not exist' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html',
    poc: 'Create S3 bucket with the same name in any region'
  },
  {
    service: 'AWS Elastic Beanstalk',
    description: 'AWS Elastic Beanstalk environment',
    cnames: ['*.elasticbeanstalk.com'],
    fingerprints: [
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Create new Elastic Beanstalk environment with same subdomain'
  },
  {
    service: 'Azure',
    description: 'Microsoft Azure web apps',
    cnames: [
      '*.azurewebsites.net',
      '*.cloudapp.azure.com',
      '*.cloudapp.net',
      '*.azure-api.net',
      '*.azurecontainer.io',
      '*.azureedge.net',
      '*.azurefd.net',
      '*.blob.core.windows.net',
      '*.trafficmanager.net'
    ],
    fingerprints: [
      { type: 'http_body', pattern: 'Error 404 - Web app not found' },
      { type: 'http_body', pattern: 'The resource you are looking for has been removed' },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Register the subdomain via Azure Portal'
  },
  {
    service: 'Google Cloud Storage',
    description: 'Google Cloud Storage bucket',
    cnames: ['*.storage.googleapis.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'NoSuchBucket' },
      { type: 'http_body', pattern: 'The specified bucket does not exist' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create GCS bucket with the same name'
  },

  // === Hosting & CDN ===
  {
    service: 'GitHub Pages',
    description: 'GitHub Pages hosting',
    cnames: ['*.github.io', '*.githubusercontent.com'],
    fingerprints: [
      { type: 'http_body', pattern: "There isn't a GitHub Pages site here" },
      { type: 'http_body', pattern: 'For root URLs (like http://example.com/)' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    documentation: 'https://docs.github.com/en/pages',
    poc: 'Create repository and configure GitHub Pages with custom domain'
  },
  {
    service: 'GitLab Pages',
    description: 'GitLab Pages hosting',
    cnames: ['*.gitlab.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'The page you\'re looking for could not be found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: false, // Requires namespace ownership
    documentation: 'https://docs.gitlab.com/ee/user/project/pages/'
  },
  {
    service: 'Heroku',
    description: 'Heroku cloud platform',
    cnames: ['*.herokuapp.com', '*.herokussl.com', '*.herokudns.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'No such app' },
      { type: 'http_body', pattern: 'no-such-app' },
      { type: 'http_body', pattern: "There's nothing here, yet." },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Create Heroku app and add custom domain'
  },
  {
    service: 'Vercel',
    description: 'Vercel (formerly ZEIT/Now)',
    cnames: ['*.vercel.app', '*.now.sh', 'cname.vercel-dns.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'The deployment could not be found' },
      { type: 'http_body', pattern: 'DEPLOYMENT_NOT_FOUND' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Add domain in Vercel project settings'
  },
  {
    service: 'Netlify',
    description: 'Netlify hosting platform',
    cnames: ['*.netlify.app', '*.netlify.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Not Found - Request ID:' },
      { type: 'http_body', pattern: 'Page Not Found' }
    ],
    takeoverPossible: true,
    poc: 'Add custom domain in Netlify site settings'
  },
  {
    service: 'Surge.sh',
    description: 'Surge static hosting',
    cnames: ['*.surge.sh'],
    fingerprints: [
      { type: 'http_body', pattern: 'project not found' },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Deploy to surge with the claimed domain'
  },
  {
    service: 'Fastly',
    description: 'Fastly CDN',
    cnames: ['*.fastly.net', '*.fastlylb.net'],
    fingerprints: [
      { type: 'http_body', pattern: 'Fastly error: unknown domain' },
      { type: 'http_status', value: 500 }
    ],
    takeoverPossible: true,
    poc: 'Add domain to Fastly service'
  },
  {
    service: 'Pantheon',
    description: 'Pantheon hosting',
    cnames: ['*.pantheonsite.io', '*.pantheon.io'],
    fingerprints: [
      { type: 'http_body', pattern: '404 error unknown site' },
      { type: 'http_body', pattern: 'The gods are wise' }
    ],
    takeoverPossible: true,
    poc: 'Add domain to Pantheon site'
  },

  // === E-commerce ===
  {
    service: 'Shopify',
    description: 'Shopify e-commerce',
    cnames: ['*.myshopify.com', 'shops.myshopify.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, this shop is currently unavailable' },
      { type: 'http_body', pattern: 'Only one step left!' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create Shopify store and add custom domain'
  },
  {
    service: 'BigCommerce',
    description: 'BigCommerce platform',
    cnames: ['*.bigcommerce.com', '*.mybigcommerce.com'],
    fingerprints: [
      { type: 'http_body', pattern: '<h1>Oops!</h1>' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: false,
    documentation: 'Requires store verification'
  },

  // === Marketing & CMS ===
  {
    service: 'Unbounce',
    description: 'Unbounce landing pages',
    cnames: ['*.unbouncepages.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'The requested URL was not found on this server' },
      { type: 'http_body', pattern: 'The page you were looking for doesn\'t exist' }
    ],
    takeoverPossible: true,
    poc: 'Add custom domain in Unbounce settings'
  },
  {
    service: 'HubSpot',
    description: 'HubSpot CMS',
    cnames: ['*.hubspot.net', '*.hs-sites.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Domain not found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: false,
    documentation: 'Requires HubSpot account verification'
  },
  {
    service: 'Webflow',
    description: 'Webflow CMS',
    cnames: ['*.webflow.io', 'proxy-ssl.webflow.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'The page you are looking for doesn\'t exist' },
      { type: 'http_body', pattern: 'page-not-found' }
    ],
    takeoverPossible: true,
    poc: 'Add domain in Webflow project settings'
  },
  {
    service: 'Ghost',
    description: 'Ghost blogging platform',
    cnames: ['*.ghost.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'The thing you were looking for is no longer here' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Add custom domain in Ghost admin'
  },
  {
    service: 'Tumblr',
    description: 'Tumblr blogging',
    cnames: ['*.tumblr.com', 'domains.tumblr.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'There\'s nothing here.' },
      { type: 'http_body', pattern: 'Whatever you were looking for doesn\'t currently exist' }
    ],
    takeoverPossible: true,
    poc: 'Register Tumblr blog and add custom domain'
  },
  {
    service: 'WordPress.com',
    description: 'WordPress.com hosted blogs',
    cnames: ['*.wordpress.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Do you want to register' }
    ],
    takeoverPossible: true,
    poc: 'Register WordPress.com blog with matching subdomain'
  },

  // === Support & Helpdesk ===
  {
    service: 'Zendesk',
    description: 'Zendesk support',
    cnames: ['*.zendesk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Help Center Closed' },
      { type: 'http_body', pattern: 'this help center no longer exists' }
    ],
    takeoverPossible: true,
    poc: 'Create Zendesk account and claim subdomain'
  },
  {
    service: 'Freshdesk',
    description: 'Freshdesk support',
    cnames: ['*.freshdesk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'There is no helpdesk here!' },
      { type: 'http_body', pattern: 'May be this is still fresh!' }
    ],
    takeoverPossible: false,
    documentation: 'Requires account verification'
  },
  {
    service: 'Intercom',
    description: 'Intercom help center',
    cnames: ['*.intercom.help', 'custom.intercom.help'],
    fingerprints: [
      { type: 'http_body', pattern: 'This page is reserved for' },
      { type: 'http_body', pattern: 'Uh oh. That page doesn\'t exist' }
    ],
    takeoverPossible: true,
    poc: 'Add domain in Intercom settings'
  },

  // === Other Services ===
  {
    service: 'Fly.io',
    description: 'Fly.io app platform',
    cnames: ['*.fly.dev'],
    fingerprints: [
      { type: 'http_status', value: 404 },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Create fly app and add certificate'
  },
  {
    service: 'Render',
    description: 'Render cloud platform',
    cnames: ['*.onrender.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Not Found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Add custom domain in Render dashboard'
  },
  {
    service: 'Railway',
    description: 'Railway app platform',
    cnames: ['*.railway.app', '*.up.railway.app'],
    fingerprints: [
      { type: 'http_body', pattern: 'Application not found' },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Deploy app and add custom domain'
  },
  {
    service: 'Cargo Collective',
    description: 'Cargo portfolio sites',
    cnames: ['*.cargo.site', '*.cargocollective.com'],
    fingerprints: [
      { type: 'http_body', pattern: '404 Not Found' },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Create Cargo site and add domain'
  },
  {
    service: 'Squarespace',
    description: 'Squarespace website builder',
    cnames: ['*.squarespace.com', 'ext-cust.squarespace.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'No Such Account' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: false,
    documentation: 'Requires domain verification'
  },
  {
    service: 'Bitbucket',
    description: 'Bitbucket cloud pages',
    cnames: ['*.bitbucket.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Repository not found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create repository and enable pages'
  },
  {
    service: 'Statuspage',
    description: 'Atlassian Statuspage',
    cnames: ['*.statuspage.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Status page pushed a b' },
      { type: 'http_body', pattern: 'You are being redirected' },
      { type: 'http_status', value: 302 }
    ],
    takeoverPossible: true,
    poc: 'Create statuspage and add custom domain'
  },
  {
    service: 'Tilda',
    description: 'Tilda website builder',
    cnames: ['*.tilda.ws'],
    fingerprints: [
      { type: 'http_body', pattern: 'Please renew your subscription' },
      { type: 'dns_nxdomain' }
    ],
    takeoverPossible: true,
    poc: 'Create Tilda project with custom domain'
  },
  {
    service: 'Wix',
    description: 'Wix website builder',
    cnames: ['*.wixsite.com', '*.wix.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Error ConnectYourDomain occurred' },
      { type: 'http_body', pattern: 'looks like there is no site here' }
    ],
    takeoverPossible: false,
    documentation: 'Requires domain verification'
  },
  {
    service: 'Strikingly',
    description: 'Strikingly website builder',
    cnames: ['*.strikinglydns.com', '*.s.strikinglydns.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'page not found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create Strikingly site with custom domain'
  },
  {
    service: 'UserVoice',
    description: 'UserVoice feedback',
    cnames: ['*.uservoice.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'This UserVoice subdomain is currently available!' }
    ],
    takeoverPossible: true,
    poc: 'Create UserVoice account with subdomain'
  },
  {
    service: 'Kayako',
    description: 'Kayako helpdesk',
    cnames: ['*.kayako.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Support Center' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: false,
    documentation: 'Requires account verification'
  },
  {
    service: 'Desk.com',
    description: 'Salesforce Desk.com',
    cnames: ['*.desk.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, We Couldn\'t Find That Page' },
      { type: 'http_body', pattern: 'Please try again or visit our Help Center' }
    ],
    takeoverPossible: false,
    documentation: 'Service deprecated, check with Salesforce'
  },
  {
    service: 'Feedpress',
    description: 'Feedpress podcast hosting',
    cnames: ['*.redirect.feedpress.me'],
    fingerprints: [
      { type: 'http_body', pattern: 'The feed has not been found' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create feed with custom domain'
  },
  {
    service: 'Canny',
    description: 'Canny feedback',
    cnames: ['*.canny.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Company Not Found' },
      { type: 'http_body', pattern: 'There is no such company' }
    ],
    takeoverPossible: true,
    poc: 'Create Canny board with matching subdomain'
  },
  {
    service: 'LaunchRock',
    description: 'LaunchRock landing pages',
    cnames: ['*.launchrock.com'],
    fingerprints: [
      { type: 'http_body', pattern: "It looks like you may have taken a wrong turn somewhere" }
    ],
    takeoverPossible: true,
    poc: 'Create LaunchRock page with custom domain'
  },
  {
    service: 'Agile CRM',
    description: 'Agile CRM landing pages',
    cnames: ['*.agilecrm.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Sorry, this page is no longer available' }
    ],
    takeoverPossible: true,
    poc: 'Create landing page in Agile CRM'
  },
  {
    service: 'Airee',
    description: 'Airee.ru CDN',
    cnames: ['*.airee.ru'],
    fingerprints: [
      { type: 'http_body', pattern: 'Ошибка 402. Оплата не manufacturers' }
    ],
    takeoverPossible: true,
    poc: 'Register with Airee'
  },
  {
    service: 'Anima',
    description: 'Anima app',
    cnames: ['*.animaapp.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'Missing Website' },
      { type: 'http_body', pattern: 'If this is your website' }
    ],
    takeoverPossible: true,
    poc: 'Deploy to Anima with custom domain'
  },
  {
    service: 'Kinsta',
    description: 'Kinsta WordPress hosting',
    cnames: ['*.kinsta.cloud'],
    fingerprints: [
      { type: 'http_body', pattern: 'No Site For Domain' }
    ],
    takeoverPossible: true,
    poc: 'Add domain to Kinsta site'
  },
  {
    service: 'Landingi',
    description: 'Landingi landing pages',
    cnames: ['*.landingi.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'It looks like you\'re lost' }
    ],
    takeoverPossible: true,
    poc: 'Create landing page with custom domain'
  },
  {
    service: 'Smartling',
    description: 'Smartling translation',
    cnames: ['*.smartling.com'],
    fingerprints: [
      { type: 'http_body', pattern: 'Domain is not configured' }
    ],
    takeoverPossible: true,
    poc: 'Contact Smartling support to claim'
  },
  {
    service: 'Read the Docs',
    description: 'Read the Docs hosting',
    cnames: ['*.readthedocs.io', 'readthedocs.io'],
    fingerprints: [
      { type: 'http_body', pattern: 'unknown to Read the Docs' },
      { type: 'http_status', value: 404 }
    ],
    takeoverPossible: true,
    poc: 'Create project and add custom domain'
  }
];

/**
 * Find matching fingerprint for a CNAME
 */
export function findServiceByCname(cname: string): ServiceFingerprint | null {
  const lowerCname = cname.toLowerCase();
  
  for (const fp of fingerprints) {
    for (const pattern of fp.cnames) {
      // Convert glob pattern to regex
      const regexPattern = pattern
        .replace(/\./g, '\\.')
        .replace(/\*/g, '.*');
      const regex = new RegExp(`^${regexPattern}$`, 'i');
      
      if (regex.test(lowerCname)) {
        return fp;
      }
    }
  }
  
  return null;
}

/**
 * Get all fingerprints
 */
export function getAllFingerprints(): ServiceFingerprint[] {
  return fingerprints;
}

/**
 * Get fingerprint by service name
 */
export function getServiceByName(name: string): ServiceFingerprint | null {
  return fingerprints.find(fp => 
    fp.service.toLowerCase() === name.toLowerCase()
  ) || null;
}
