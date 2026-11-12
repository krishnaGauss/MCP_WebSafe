import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SERVER_INFO } from '../src/mcp/server.js';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const server = JSON.parse(fs.readFileSync('server.json', 'utf8'));

describe('release metadata', () => {
  it('keeps versions and names in sync across package.json, server.json and the MCP server', () => {
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(server.packages[0].identifier).toBe(pkg.name);
    expect(server.name).toBe(pkg.mcpName);
    expect(SERVER_INFO.version).toBe(pkg.version);
  });

  it('fits MCP Registry limits', () => {
    expect(server.description.length).toBeLessThanOrEqual(100);
  });
});
