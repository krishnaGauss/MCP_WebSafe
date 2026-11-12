import pino from 'pino';

// stdout carries the MCP protocol over STDIO, so logs must go to stderr (fd 2).
export const logger = pino(
  { name: 'geo-shield-mcp', level: process.env.GEO_SHIELD_LOG_LEVEL ?? 'info' },
  pino.destination(2),
);
