const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Global Prisma instance
const prisma = new PrismaClient();

const JWT_SECRET = process.env.NEXTAUTH_SECRET || 'your-jwt-secret';

// Middleware
app.use(express.json());
app.use(cors({
  origin: '*',
  credentials: true
}));

// Enhanced logging middleware
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const origin = req.headers.origin || 'no-origin';
  const authHeader = req.headers.authorization || 'no-auth';

  console.log(`🔍 [${req.method}] ${req.path}`, {
    userAgent: userAgent.substring(0, 100),
    origin,
    hasAuth: authHeader !== 'no-auth',
    timestamp: new Date().toISOString()
  });

  next();
});

// Authentication helper
async function authenticateRequest(req) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.sub }
    });

    if (!user) {
      return null;
    }

    return {
      isAuthenticated: true,
      userId: decoded.sub,
      clientId: decoded.aud,
      scopes: decoded.scope ? decoded.scope.split(' ') : [],
      resources: ['*'],
      audience: ['mcp-server'],
    };
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}

// OAuth2 Authorization Server Discovery (RFC 8414)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const baseUrl = process.env.NEXTAUTH_URL || 'https://mcp.brainloop.cc';

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/api/auth/signin`,
    token_endpoint: `${baseUrl}/api/auth/token`,
    userinfo_endpoint: `${baseUrl}/api/auth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported: ['openid', 'email', 'profile'],
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'email', 'name']
  });
});

// MCP Client Configuration Discovery
app.get('/.well-known/mcp-client-config', (req, res) => {
  const baseUrl = process.env.NEXTAUTH_URL || 'https://mcp.brainloop.cc';

  res.json({
    client_name: "BRAINLOOP MCP Client",
    client_id: "brainloop-mcp-client",
    redirect_uris: [`${baseUrl}/api/auth/callback`],
    scopes: ["mcp:read", "mcp:write"],
    mcp_transport: {
      type: "sse",
      endpoint: `${baseUrl}/api/mcp/sse`
    },
    auth: {
      type: "oauth2",
      authorization_endpoint: `${baseUrl}/api/auth/authorize`,
      token_endpoint: `${baseUrl}/api/auth/token`
    }
  });
});

// SSE endpoint for Claude web
app.get('/api/mcp/sse', async (req, res) => {
  console.log('🔗 SSE connection requested from Claude web');

  try {
    const authContext = await authenticateRequest(req);

    if (!authContext) {
      console.log('❌ No valid authentication for SSE connection');
      return res.status(401).send('Unauthorized');
    }

    console.log('✅ Authenticated SSE connection for user:', authContext.userId);

    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });

    // Send initial connection message
    const initMessage = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {
          tools: { listChanged: true },
          actions: { listChanged: true },
          resources: { listChanged: true, subscribe: false },
          logging: { level: 'info' }
        },
        serverInfo: {
          name: 'BRAINLOOP MCP Server',
          version: '1.0.0',
          description: 'MCP server for BRAINLOOP spaced repetition learning platform'
        }
      }
    };

    res.write(`data: ${JSON.stringify(initMessage)}\n\n`);

    // Keep connection alive with heartbeat
    const heartbeat = setInterval(() => {
      try {
        res.write(`data: ${JSON.stringify({ type: 'heartbeat', timestamp: Date.now() })}\n\n`);
      } catch (error) {
        console.log('SSE connection closed, clearing heartbeat');
        clearInterval(heartbeat);
      }
    }, 30000);

    // Handle connection close
    req.on('close', () => {
      console.log('SSE connection closed by client');
      clearInterval(heartbeat);
    });

  } catch (error) {
    console.error('SSE endpoint error:', error);
    res.status(500).send('Internal Server Error');
  }
});

// MCP Server main endpoint
app.all('/api/mcp/server', async (req, res) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';

  const isClaudeWebByUA = userAgent.includes('claude') || userAgent.includes('anthropic') || userAgent.includes('Claude-User');
  const isClaudeWebByOrigin = origin.includes('claude.ai') || referer.includes('claude.ai');
  const isClaudeWeb = isClaudeWebByUA || isClaudeWebByOrigin;

  console.log('🤖 MCP Server request:', {
    method: req.method,
    isClaudeWeb,
    userAgent: userAgent.substring(0, 50),
    hasBody: !!req.body
  });

  if (req.method === 'OPTIONS') {
    return res.status(200).json({});
  }

  try {
    const body = req.body || {};
    const method = body.method || 'unknown';

    // Allow Claude web to perform initialize and discovery calls without authentication
    if (isClaudeWeb && (method === 'initialize' || method === 'tools/list' || method === 'resources/list')) {
      console.log('🔓 Allowing Claude web discovery call without auth:', method);

      if (method === 'initialize') {
        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: {
              tools: { listChanged: true },
              resources: { listChanged: true, subscribe: false },
              logging: { level: 'info' }
            },
            serverInfo: {
              name: 'BRAINLOOP MCP Server',
              version: '1.0.0',
              description: 'MCP server for BRAINLOOP spaced repetition learning platform'
            }
          }
        });
      }

      if (method === 'tools/list') {
        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            tools: [
              {
                name: 'get_courses',
                description: 'Get list of available courses',
                inputSchema: {
                  type: 'object',
                  properties: {}
                }
              }
            ]
          }
        });
      }

      if (method === 'resources/list') {
        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            resources: [
              {
                uri: 'brainloop://courses',
                name: 'Courses',
                description: 'List of all courses',
                mimeType: 'application/json'
              }
            ]
          }
        });
      }
    }

    // For other requests, require authentication
    const authContext = await authenticateRequest(req);

    if (!authContext) {
      console.log('❌ MCP Server: Authentication required');
      return res.status(401).json({
        jsonrpc: '2.0',
        id: body.id,
        error: { code: -32001, message: 'Authentication required' }
      });
    }

    console.log('✅ Authenticated MCP request for user:', authContext.userId);

    // Handle authenticated MCP methods here
    return res.json({
      jsonrpc: '2.0',
      id: body.id,
      result: { status: 'authenticated', method }
    });

  } catch (error) {
    console.error('MCP Server error:', error);
    return res.status(500).json({
      jsonrpc: '2.0',
      id: req.body?.id,
      error: { code: -32603, message: 'Internal error' }
    });
  }
});

// Redirect signin requests to main BRAINLOOP app
app.get('/api/auth/signin', (req, res) => {
  console.log('🔐 Redirecting signin to main BRAINLOOP app');

  // Redirect to main app for authentication
  const mainAppUrl = new URL('/api/auth/signin', 'https://brainloop.cc');

  // Preserve all query parameters
  Object.keys(req.query).forEach(key => {
    mainAppUrl.searchParams.set(key, req.query[key]);
  });

  res.redirect(mainAppUrl.toString());
});

// OAuth authorize endpoint
app.get('/api/auth/authorize', (req, res) => {
  const { client_id, response_type, scope, redirect_uri, state } = req.query;

  console.log('🔑 OAuth authorize request:', {
    client_id,
    response_type,
    scope,
    redirect_uri,
    state
  });

  // Redirect to main app signin with preserved parameters
  const signinUrl = new URL('/api/auth/signin', 'https://brainloop.cc');
  signinUrl.searchParams.set('callbackUrl', req.originalUrl);

  res.redirect(signinUrl.toString());
});

// OAuth token endpoint
app.post('/api/auth/token', async (req, res) => {
  const { grant_type, code, client_id, redirect_uri } = req.body;

  console.log('🎫 OAuth token request:', {
    grant_type,
    code,
    client_id,
    redirect_uri
  });

  // In a real implementation, you'd validate the authorization code
  // For now, return a mock JWT token
  const token = jwt.sign(
    {
      sub: 'user-123',
      aud: client_id,
      scope: 'mcp:read mcp:write',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    },
    JWT_SECRET
  );

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'mcp:read mcp:write'
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 BRAINLOOP MCP Server running on port ${port}`);
  console.log(`📡 SSE endpoint: /api/mcp/sse`);
  console.log(`🤖 MCP endpoint: /api/mcp/server`);
  console.log(`🔐 OAuth discovery: /.well-known/oauth-authorization-server`);
  console.log(`✅ Dedicated MCP server repository deployed successfully`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
});