#!/usr/bin/env node

/**
 * Skills-Bridge Remote SSE/HTTP Server
 *
 * Exposes the skills-bridge MCP server over HTTP for remote access.
 * Supports both Streamable HTTP (recommended) and legacy SSE transports.
 *
 * Usage:
 *   MCP_AUTH_TOKEN=secret node dist/skills-bridge/sse-server.js
 *
 * Endpoints:
 *   POST /mcp              - Streamable HTTP MCP endpoint (initialize, tool calls)
 *   GET  /mcp              - Streamable HTTP SSE stream (server-initiated messages)
 *   DELETE /mcp            - Session termination
 *   GET  /sse              - Legacy SSE endpoint (establishes SSE connection)
 *   POST /message?sessionId=xxx - Legacy SSE message endpoint
 *   GET  /health           - Health check (no auth required)
 */

import { createServer as createHttpServer, IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { createSkillsBridgeServer } from './server.js';

// ── Configuration ────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || '10', 10);

if (!AUTH_TOKEN) {
  console.error('FATAL: MCP_AUTH_TOKEN environment variable is required.');
  console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// ── Session Management ───────────────────────────────────────────────────────

interface SessionEntry {
  transport: StreamableHTTPServerTransport;
  server: Server;
  createdAt: number;
  lastActivity: number;
}

const sessions = new Map<string, SessionEntry>();

// Legacy SSE sessions
interface LegacySessionEntry {
  transport: SSEServerTransport;
  server: Server;
  createdAt: number;
}
const legacySessions = new Map<string, LegacySessionEntry>();

// Skill count for health checks (shared across sessions)
let totalSkillCount = 0;

// Clean up stale sessions every 5 minutes
setInterval(() => {
  const now = Date.now();
  const staleThreshold = 30 * 60 * 1000; // 30 minutes

  for (const [id, session] of sessions) {
    if (now - session.lastActivity > staleThreshold) {
      console.log(`Cleaning up stale session: ${id}`);
      session.transport.close().catch(() => {});
      session.server.close().catch(() => {});
      sessions.delete(id);
    }
  }

  for (const [id, session] of legacySessions) {
    if (now - session.createdAt > staleThreshold) {
      console.log(`Cleaning up stale legacy session: ${id}`);
      session.transport.close().catch(() => {});
      session.server.close().catch(() => {});
      legacySessions.delete(id);
    }
  }
}, 5 * 60 * 1000);

// ── Helpers ──────────────────────────────────────────────────────────────────

function setCorsHeaders(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Mcp-Session-Id');
  res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
}

function checkAuth(req: IncomingMessage, res: ServerResponse): boolean {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${AUTH_TOKEN}`) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized', hint: 'Provide Bearer token in Authorization header' }));
    return false;
  }
  return true;
}

function parseBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf-8');
      if (!body) { resolve(undefined); return; }
      try { resolve(JSON.parse(body)); }
      catch (e) { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

async function createSession(): Promise<{ server: Server; transport: StreamableHTTPServerTransport; skillCount: number }> {
  const { server, skills } = createSkillsBridgeServer();

  try {
    await skills.initialize();
  } catch (error) {
    console.error('Skills initialization warning:', error);
  }

  const skillCount = skills.getAvailableSkills().length;
  totalSkillCount = skillCount;

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
  });

  await server.connect(transport);
  return { server, transport, skillCount };
}

async function createLegacySession(res: ServerResponse): Promise<{ server: Server; transport: SSEServerTransport }> {
  const { server, skills } = createSkillsBridgeServer();

  try {
    await skills.initialize();
  } catch (error) {
    console.error('Skills initialization warning:', error);
  }

  totalSkillCount = skills.getAvailableSkills().length;

  const transport = new SSEServerTransport('/message', res);
  await server.connect(transport);
  return { server, transport };
}

// ── Request Handler ──────────────────────────────────────────────────────────

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  setCorsHeaders(res);

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // ── Health check (no auth) ──
  if (pathname === '/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      version: '0.3.0',
      skills: totalSkillCount,
      activeSessions: sessions.size + legacySessions.size,
      uptime: Math.floor(process.uptime()),
      transport: 'streamable-http+sse',
    }));
    return;
  }

  // All other endpoints require auth
  if (!checkAuth(req, res)) return;

  // ── Streamable HTTP: POST /mcp ──
  if (pathname === '/mcp' && req.method === 'POST') {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    const body = await parseBody(req);

    if (sessionId && sessions.has(sessionId)) {
      // Existing session
      const session = sessions.get(sessionId)!;
      session.lastActivity = Date.now();
      await session.transport.handleRequest(req, res, body);
      return;
    }

    // New session (initialization)
    if (sessions.size >= MAX_SESSIONS) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Too many active sessions' }));
      return;
    }

    const { server, transport, skillCount } = await createSession();
    console.log(`New session created (${skillCount} skills loaded)`);

    await transport.handleRequest(req, res, body);

    if (transport.sessionId) {
      sessions.set(transport.sessionId, {
        transport,
        server,
        createdAt: Date.now(),
        lastActivity: Date.now(),
      });
      console.log(`Session registered: ${transport.sessionId}`);
    }
    return;
  }

  // ── Streamable HTTP: GET /mcp (SSE stream for server notifications) ──
  if (pathname === '/mcp' && req.method === 'GET') {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
      session.lastActivity = Date.now();
      await session.transport.handleRequest(req, res);
      return;
    }
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid or missing session ID' }));
    return;
  }

  // ── Streamable HTTP: DELETE /mcp (session termination) ──
  if (pathname === '/mcp' && req.method === 'DELETE') {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (sessionId && sessions.has(sessionId)) {
      const session = sessions.get(sessionId)!;
      await session.transport.close();
      await session.server.close();
      sessions.delete(sessionId);
      console.log(`Session terminated: ${sessionId}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'session terminated' }));
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Session not found' }));
    return;
  }

  // ── Legacy SSE: GET /sse ──
  if (pathname === '/sse' && req.method === 'GET') {
    if (legacySessions.size >= MAX_SESSIONS) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Too many active sessions' }));
      return;
    }

    const { server, transport } = await createLegacySession(res);
    await transport.start();

    legacySessions.set(transport.sessionId, {
      transport,
      server,
      createdAt: Date.now(),
    });

    console.log(`Legacy SSE session created: ${transport.sessionId}`);

    // Clean up on disconnect
    req.on('close', () => {
      console.log(`Legacy SSE session disconnected: ${transport.sessionId}`);
      transport.close().catch(() => {});
      server.close().catch(() => {});
      legacySessions.delete(transport.sessionId);
    });
    return;
  }

  // ── Legacy SSE: POST /message ──
  if (pathname === '/message' && req.method === 'POST') {
    const sessionId = url.searchParams.get('sessionId');
    if (!sessionId || !legacySessions.has(sessionId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Session not found' }));
      return;
    }

    const session = legacySessions.get(sessionId)!;
    await session.transport.handlePostMessage(req, res);
    return;
  }

  // ── 404 ──
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    error: 'Not found',
    endpoints: {
      'POST /mcp': 'Streamable HTTP MCP endpoint',
      'GET /mcp': 'Streamable HTTP SSE stream',
      'DELETE /mcp': 'Session termination',
      'GET /sse': 'Legacy SSE endpoint',
      'POST /message': 'Legacy SSE message endpoint',
      'GET /health': 'Health check (no auth)',
    },
  }));
}

// ── Start Server ─────────────────────────────────────────────────────────────

const httpServer = createHttpServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (error) {
    console.error('Request error:', error);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║         Skills-Bridge Remote MCP Server v0.3.0         ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log(`║  Listening:  http://${HOST}:${PORT}`.padEnd(59) + '║');
  console.log(`║  MCP:        http://${HOST}:${PORT}/mcp`.padEnd(59) + '║');
  console.log(`║  SSE:        http://${HOST}:${PORT}/sse`.padEnd(59) + '║');
  console.log(`║  Health:     http://${HOST}:${PORT}/health`.padEnd(59) + '║');
  console.log(`║  Auth:       Bearer token required`.padEnd(59) + '║');
  console.log(`║  Sessions:   max ${MAX_SESSIONS}`.padEnd(59) + '║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down...');
  for (const [, session] of sessions) {
    await session.transport.close().catch(() => {});
    await session.server.close().catch(() => {});
  }
  for (const [, session] of legacySessions) {
    await session.transport.close().catch(() => {});
    await session.server.close().catch(() => {});
  }
  httpServer.close(() => process.exit(0));
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down...');
  httpServer.close(() => process.exit(0));
});
