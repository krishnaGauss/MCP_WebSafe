/**
 * Runs the fixture site standalone for manual testing with the MCP Inspector or Claude:
 *   npm run fixtures
 * then start the server with GEO_SHIELD_FIXTURE_ALLOW set to the printed value.
 */
import { routes, startFixtureSite } from './site.ts';

const port = Number(process.env.FIXTURE_PORT ?? 4599);
const site = await startFixtureSite(port);
console.error(`Fixture site: ${site.site}  (external domain: ${site.evil})`);
console.error(`GEO_SHIELD_FIXTURE_ALLOW=${site.allow.join(',')}`);
console.error('Pages:', Object.keys(routes(site.evil)).join(' '));
