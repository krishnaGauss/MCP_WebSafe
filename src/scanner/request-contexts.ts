import type { RequestContextName } from '../types/scan.js';

export interface RequestContext {
  name: RequestContextName;
  description: string;
  headers: Record<string, string>;
  simulated: boolean;
}

const CHROME_DESKTOP =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const CHROME_MOBILE =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36';
const CRAWLER_SIM =
  'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

const BASE = {
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
};

export const REQUEST_CONTEXT_PRESETS: Record<RequestContextName, RequestContext> = {
  desktop_browser: {
    name: 'desktop_browser',
    description: 'Standard desktop Chrome browser request with no referrer.',
    headers: { ...BASE, 'user-agent': CHROME_DESKTOP },
    simulated: false,
  },
  mobile_browser: {
    name: 'mobile_browser',
    description: 'Android Chrome mobile browser request.',
    headers: { ...BASE, 'user-agent': CHROME_MOBILE },
    simulated: false,
  },
  search_referrer: {
    name: 'search_referrer',
    description: 'Desktop browser arriving from a search results page (Referer: https://www.google.com/).',
    headers: { ...BASE, 'user-agent': CHROME_DESKTOP, referer: 'https://www.google.com/' },
    simulated: true,
  },
  crawler_ua_simulated: {
    name: 'crawler_ua_simulated',
    description:
      'Request using a search-crawler user-agent string. SIMULATION ONLY: requests come from this machine, not from the search engine\'s verified IP ranges, so sites that verify crawlers by IP may respond differently to the real crawler.',
    headers: { ...BASE, 'user-agent': CRAWLER_SIM },
    simulated: true,
  },
};
