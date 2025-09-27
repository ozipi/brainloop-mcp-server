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

  console.log("🔐 Authentication attempt:", {
    hasAuthHeader: !!authHeader,
    authHeaderPrefix: authHeader ? authHeader.substring(0, 20) + "..." : "none",
    userAgent: req.headers["user-agent"]?.substring(0, 50) || "unknown"
  });

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
  console.log("🎫 Token received:", {
    tokenLength: token.length,
    tokenStart: token.substring(0, 20) + "..."
  });
    return null;
  console.log("✅ Token decoded successfully:", {
    sub: decoded.sub,
    aud: decoded.aud,
    scope: decoded.scope,
    exp: decoded.exp,
    iat: decoded.iat
  });
  }
  console.log("🔍 Scope validation:", {
    scopes,
    hasValidScope,
    requiredScopes: ["mcp:read", "mcp:write"]
  });

  const token = authHeader.substring(7);

  try {
    // Verify JWT token issued by main BRAINLOOP app
    const decoded = jwt.verify(token, JWT_SECRET);

    // Validate that the token has proper MCP scopes
    const scopes = decoded.scope ? decoded.scope.split(' ') : [];
    const hasValidScope = scopes.some(scope => scope.startsWith('mcp:'));
  console.log("✅ User authenticated successfully:", {
    userId: user.id,
    email: user.email,
    name: user.name
  });

    if (!hasValidScope) {
      console.log('❌ Token missing required MCP scopes');
      return null;
    }
  console.log("❌ Token verification failed:", {
    error: error.message,
    tokenStart: token.substring(0, 20) + "..."
  });

    const user = await prisma.user.findUnique({
      where: { id: decoded.sub }
    });

    if (!user) {
      console.log('❌ User not found in database');
      return null;
    }

    return {
      isAuthenticated: true,
      userId: decoded.sub,
      clientId: decoded.aud,
      scopes: scopes,
      resources: ['*'],
      audience: ['mcp-server'],
    };
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}

// Remove OAuth discovery - OAuth is handled by main BRAINLOOP app

// MCP Client Configuration Discovery removed - handled by main BRAINLOOP app

// MCP Client Configuration Discovery
app.get("/.well-known/mcp-client-config", (req, res) => {
  const baseUrl = process.env.NEXTAUTH_URL || "https://mcp.brainloop.cc";

  res.json({
    client_name: "BRAINLOOP MCP Client",
    client_id: "brainloop-mcp-client",
    redirect_uris: [`${baseUrl}/api/auth/callback`],
    scopes: ["mcp:read", "mcp:write"],
    mcp_transport: {
      type: "http",
      endpoint: `${baseUrl}/api/mcp/server`
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

// OAuth2 Authorization Server Discovery (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = process.env.NEXTAUTH_URL || "https://mcp.brainloop.cc";

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/api/auth/authorize`,
    token_endpoint: `${baseUrl}/api/auth/token`,
    userinfo_endpoint: `${baseUrl}/api/auth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["HS256"],
    scopes_supported: ["openid", "email", "profile", "mcp:read", "mcp:write"],
    claims_supported: ["iss", "sub", "aud", "exp", "iat", "email", "name"]
  });
});
  console.log('🔗 SSE connection requested from Claude web');

  try {
    const authContext = await authenticateRequest(req);

    if (!authContext) {

// OAuth endpoints
app.get("/api/auth/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state } = req.query;
  console.log("🔐 OAuth authorize request:", { response_type, client_id, redirect_uri, scope, state });

  if (response_type !== "code") {
    return res.status(400).json({ error: "unsupported_response_type" });
  }

  // Redirect to main BRAINLOOP app for authentication
  const mainAppUrl = "https://brainloop.cc";
  const authUrl = `${mainAppUrl}/api/auth/authorize?${new URLSearchParams(req.query).toString()}`;
  console.log("🚀 Redirecting to main app for auth:", authUrl);
  res.redirect(authUrl);
});

app.post("/api/auth/token", async (req, res) => {
  const { grant_type, code, client_id, redirect_uri } = req.body;
  console.log("🎫 OAuth token request:", { grant_type, code, client_id, redirect_uri });

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  if (!code) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    // Generate JWT token for MCP access
    const token = jwt.sign(
      {
        sub: "user-authenticated",
        aud: client_id,
        scope: "mcp:read mcp:write",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600
      },
      JWT_SECRET
    );

    res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: 3600,
      scope: "mcp:read mcp:write"
    });
  } catch (error) {
    console.error("🎫 Token generation error:", error);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/auth/userinfo", async (req, res) => {
  console.log("👤 Userinfo request received");
  try {
    const authContext = await authenticateRequest(req);
    if (!authContext) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const user = await prisma.user.findUnique({
      where: { id: authContext.userId },
      select: { id: true, name: true, email: true, image: true }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      sub: user.id,
      name: user.name,
      email: user.email,
      picture: user.image,
      email_verified: true
    });
  } catch (error) {
    console.error("Userinfo error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/.well-known/jwks.json", (req, res) => {
  console.log("🔑 JWKS request received");
  res.json({ keys: [] });
});
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
  // Add MCP-specific headers to help Claude web recognize this as MCP server
  res.setHeader("X-MCP-Version", "2024-11-05");
  res.setHeader("X-MCP-Server", "BRAINLOOP MCP Server");
  res.setHeader("X-MCP-Protocol", "json-rpc-2.0");
  res.setHeader("Content-Type", "application/json");
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
    if (isClaudeWeb && (method === 'initialize' || method === 'notifications/initialized' || method === 'tools/list' || method === 'resources/list')) {
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
              version: '2.0.3',
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

// OAuth endpoints removed - OAuth is handled by main BRAINLOOP app at brainloop.cc
// This server only handles MCP protocol requests

// Root path handler - handle MCP requests directly
app.all('/', async (req, res) => {
  console.log('🏠 Root path request - handling as MCP server request');
  
  // If it's a POST request with JSON body, handle as MCP request
  if (req.method === 'POST' && req.headers['content-type']?.includes('application/json')) {
    console.log('📨 Handling POST request as MCP server request');
    
    // Use the same logic as the MCP server endpoint
    const userAgent = req.headers['user-agent'] || 'unknown';
    const origin = req.headers.origin || '';
    const referer = req.headers.referer || '';

    const isClaudeWebByUA = userAgent.includes('claude') || userAgent.includes('anthropic') || userAgent.includes('Claude-User');
    const isClaudeWebByOrigin = origin.includes('claude.ai') || referer.includes('claude.ai');
    const isClaudeWeb = isClaudeWebByUA || isClaudeWebByOrigin;

    console.log('🤖 MCP Server request (via root):', {
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

      console.log('🔍 MCP Request details:', {
        method,
        id: body.id,
        params: body.params,
        hasAuth: !!req.headers.authorization
      });

      // Allow Claude web to perform initialize and discovery calls without authentication
      if (isClaudeWeb && (method === 'initialize' || method === 'notifications/initialized' || method === 'tools/list' || method === 'resources/list')) {
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
                version: '2.0.3',
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
                  name: 'create_course',
                  description: 'Create a new course in the BRAINLOOP system',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      title: { type: 'string', description: 'Course title' },
                      description: { type: 'string', description: 'Course description' },
                      author: { type: 'string', description: 'Course author' },
                      tags: { type: 'array', items: { type: 'string' }, description: 'Course tags' },
                      hero: { type: 'string', description: 'Hero image URL' },
                      icon: { type: 'string', description: 'Course icon URL' },
                      isPrivate: { type: 'boolean', description: 'Whether the course is private' },
                      userId: { type: 'string', description: 'User ID of the course creator' },
                    },
                    required: ['title', 'description', 'userId'],
                  },
                },
                {
                  name: 'get_user_progress',
                  description: 'Get learning progress for a specific user',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      userId: { type: 'string', description: 'User ID' },
                      courseId: { type: 'string', description: 'Optional course ID to filter by' },
                    },
                    required: ['userId'],
                  },
                },
                {
                  name: 'update_progress',
                  description: 'Update learning progress for a lesson',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      userId: { type: 'string', description: 'User ID' },
                      lessonId: { type: 'string', description: 'Lesson ID' },
                      status: { type: 'string', description: 'Progress status (not_started, in_progress, completed)' },
                    },
                    required: ['userId', 'lessonId', 'status'],
                  },
                },
                {
                  name: 'get_review_schedule',
                  description: 'Get the review schedule for a user based on nextReview dates',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      userId: { type: 'string', description: 'User ID' },
                      courseId: { type: 'string', description: 'Optional course ID to filter by' },
                    },
                    required: ['userId'],
                  },
                },
                {
                  name: 'enroll_user',
                  description: 'Enroll a user in a course',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      userId: { type: 'string', description: 'User ID' },
                      courseId: { type: 'string', description: 'Course ID' },
                    },
                    required: ['userId', 'courseId'],
                  },
                },
                {
                  name: 'get_user_enrollments',
                  description: 'Get all courses a user is enrolled in',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      userId: { type: 'string', description: 'User ID' },
                    },
                    required: ['userId'],
                  },
                },
                {
                  name: 'create_course_from_json',
                  description: 'Create a new course and all its units/lessons from a single JSON object',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      courseData: { 
                        type: 'object', 
                        description: 'Complete course JSON structure with title, description, units, lessons, etc.' 
                      },
                    },
                    required: ['courseData'],
                  },
                },
                {
                  name: 'get_course_structure',
                  description: 'Get the current structure of a course (units and lesson counts)',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      courseId: { 
                        type: 'string', 
                        description: 'ID of the course to get structure for' 
                      },
                    },
                    required: ['courseId'],
                  },
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
                  description: 'All available courses in the BRAINLOOP system',
                  mimeType: 'application/json',
                },
                {
                  uri: 'brainloop://users',
                  name: 'Users',
                  description: 'All users in the BRAINLOOP system',
                  mimeType: 'application/json',
                },
                {
                  uri: 'brainloop://progress',
                  name: 'Progress',
                  description: 'All learning progress records',
                  mimeType: 'application/json',
                },
              ],
            }
          });
        }


        if (method === 'resources/read') {
          const { uri } = body.params || {};
          console.log('📖 Resource read:', { uri });

          if (uri === 'brainloop://courses') {
            return res.json({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                contents: [
                  {
                    uri: 'brainloop://courses',
                    mimeType: 'application/json',
                    text: JSON.stringify({
                      courses: [
                        { id: 1, title: 'JavaScript Fundamentals', description: 'Learn the basics of JavaScript' },
                        { id: 2, title: 'React Development', description: 'Build modern web apps with React' },
                        { id: 3, title: 'Node.js Backend', description: 'Server-side JavaScript development' },
                        { id: 4, title: 'Database Design', description: 'Design and optimize databases' }
                      ]
                    }, null, 2)
                  }
                ]
              }
            });
          }

          return res.json({
            jsonrpc: '2.0',
            id: body.id,
            error: {
              code: -32602,
              message: `Resource not found: ${uri}`
            }
          });
        }

        if (method === 'notifications/initialized') {
          console.log('✅ Client initialized notification received');
          return res.json({
            jsonrpc: '2.0',
            id: body.id,
            result: {}
          });
        }

        // If we get here, it's a method we don't handle without auth
        console.log('❌ Unhandled method without auth:', method);
        console.log('🔍 Full request body:', JSON.stringify(body, null, 2));
        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          error: {
            code: -32601,
            message: `Method not found: ${method}`
          }
        });
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
  }
  
  // For other requests, return MCP server info
  res.json({
    name: 'BRAINLOOP MCP Server',
    version: '2.0.3',
    description: 'Dedicated MCP protocol server for BRAINLOOP (OAuth handled by main app)',
    endpoints: {
      mcp: '/api/mcp/server',
      sse: '/api/mcp/sse',
      health: '/health'
    },
    auth_note: 'Authentication handled by https://brainloop.cc'
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
  console.log(`🔑 Authentication: Handled by https://brainloop.cc`);
  console.log(`✅ Dedicated MCP protocol server v2.0.1 deployed successfully`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
});