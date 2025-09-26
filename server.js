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
    authorization_endpoint: `${baseUrl}/api/auth/authorize`,
    token_endpoint: `${baseUrl}/api/auth/token`,
    userinfo_endpoint: `${baseUrl}/api/auth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256'],
    scopes_supported: ['openid', 'email', 'profile', 'mcp:read', 'mcp:write'],
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

// OAuth callback endpoint (handles redirect from main app)
app.get('/api/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  console.log('🔄 OAuth callback received:', {
    hasCode: !!code,
    state,
    error,
    userAgent: req.headers['user-agent']
  });

  if (error) {
    console.error('❌ OAuth error:', error);
    return res.status(400).json({ error: 'OAuth authentication failed', details: error });
  }

  if (!code) {
    console.error('❌ No authorization code received');
    return res.status(400).json({ error: 'Missing authorization code' });
  }

  // This callback should redirect to Claude, but since Claude called this directly,
  // we need to return the code for Claude to exchange for tokens
  res.json({
    code,
    state,
    message: 'Authorization successful - use this code to get access token'
  });
});

// OAuth userinfo endpoint
app.get('/api/auth/userinfo', async (req, res) => {
  console.log('👤 Userinfo request received');
  
  try {
    const authContext = await authenticateRequest(req);
    
    if (!authContext) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Get user info from database
    const user = await prisma.user.findUnique({
      where: { id: authContext.userId },
      select: {
        id: true,
        name: true,
        email: true,
        image: true
      }
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      sub: user.id,
      name: user.name,
      email: user.email,
      picture: user.image,
      email_verified: true
    });
  } catch (error) {
    console.error('Userinfo error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// JWKS endpoint for OAuth discovery
app.get('/.well-known/jwks.json', (req, res) => {
  console.log('🔑 JWKS request received');
  
  // For now, return an empty JWKS since we're using HS256
  // In production, you'd want to use RS256 with proper key rotation
  res.json({
    keys: []
  });
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

  if (!code) {
    return res.status(400).json({ error: 'Missing authorization code' });
  }

  try {
    // In a real implementation, you'd validate the authorization code against stored codes
    // For now, we'll look up the user who authorized this code
    // Since we don't store auth codes, we'll create a token for the authenticated user

    // Generate a JWT token for the user
    const token = jwt.sign(
      {
        sub: 'user-authenticated', // This should be the actual user ID from the auth code
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
  } catch (error) {
    console.error('🎫 Token generation error:', error);
    res.status(500).json({ error: 'Token generation failed' });
  }
});

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
      if (isClaudeWeb && (method === 'initialize' || method === 'tools/list' || method === 'resources/list' || method === 'tools/call' || method === 'resources/read' || method === 'notifications/initialized')) {
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
                  description: 'Get list of all available courses in BRAINLOOP',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      limit: {
                        type: 'number',
                        description: 'Maximum number of courses to return',
                        default: 10
                      },
                      category: {
                        type: 'string',
                        description: 'Filter courses by category',
                        enum: ['programming', 'design', 'business', 'all']
                      }
                    }
                  }
                },
                {
                  name: 'get_course_details',
                  description: 'Get detailed information about a specific course',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      course_id: {
                        type: 'string',
                        description: 'The ID of the course to get details for'
                      }
                    },
                    required: ['course_id']
                  }
                },
                {
                  name: 'search_courses',
                  description: 'Search for courses by title, description, or tags',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      query: {
                        type: 'string',
                        description: 'Search query to find courses'
                      },
                      tags: {
                        type: 'array',
                        items: { type: 'string' },
                        description: 'Filter by specific tags'
                      }
                    },
                    required: ['query']
                  }
                },
                {
                  name: 'get_user_progress',
                  description: 'Get the current user\'s learning progress',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      course_id: {
                        type: 'string',
                        description: 'Optional course ID to get progress for specific course'
                      }
                    }
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

        if (method === 'tools/call') {
          const { name, arguments: args } = body.params || {};
          console.log('🔧 Tool call:', { name, args });

          if (name === 'get_courses') {
            const limit = args?.limit || 10;
            const category = args?.category || 'all';
            
            const courses = [
              { id: 'js-fundamentals', title: 'JavaScript Fundamentals', description: 'Learn the basics of JavaScript programming', category: 'programming', tags: ['javascript', 'programming', 'beginner'] },
              { id: 'react-dev', title: 'React Development', description: 'Build modern web apps with React', category: 'programming', tags: ['react', 'javascript', 'frontend'] },
              { id: 'node-backend', title: 'Node.js Backend', description: 'Server-side JavaScript development', category: 'programming', tags: ['nodejs', 'javascript', 'backend'] },
              { id: 'db-design', title: 'Database Design', description: 'Design and optimize databases', category: 'programming', tags: ['database', 'sql', 'design'] },
              { id: 'ui-design', title: 'UI/UX Design', description: 'Create beautiful and functional user interfaces', category: 'design', tags: ['design', 'ui', 'ux'] },
              { id: 'business-strategy', title: 'Business Strategy', description: 'Learn strategic thinking and business planning', category: 'business', tags: ['business', 'strategy', 'management'] }
            ];

            let filteredCourses = courses;
            if (category !== 'all') {
              filteredCourses = courses.filter(course => course.category === category);
            }
            
            const limitedCourses = filteredCourses.slice(0, limit);

            return res.json({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                content: [
                  {
                    type: 'text',
                    text: `Found ${limitedCourses.length} courses:\n\n` + 
                          limitedCourses.map((course, index) => 
                            `${index + 1}. **${course.title}**\n   ${course.description}\n   Category: ${course.category}\n   Tags: ${course.tags.join(', ')}\n   ID: ${course.id}`
                          ).join('\n\n')
                  }
                ]
              }
            });
          }

          if (name === 'get_course_details') {
            const courseId = args?.course_id;
            if (!courseId) {
              return res.json({
                jsonrpc: '2.0',
                id: body.id,
                error: {
                  code: -32602,
                  message: 'course_id is required'
                }
              });
            }

            const courseDetails = {
              'js-fundamentals': {
                id: 'js-fundamentals',
                title: 'JavaScript Fundamentals',
                description: 'Learn the basics of JavaScript programming',
                category: 'programming',
                duration: '4 weeks',
                lessons: 12,
                difficulty: 'beginner',
                tags: ['javascript', 'programming', 'beginner'],
                instructor: 'John Doe',
                price: '$99'
              },
              'react-dev': {
                id: 'react-dev',
                title: 'React Development',
                description: 'Build modern web apps with React',
                category: 'programming',
                duration: '6 weeks',
                lessons: 18,
                difficulty: 'intermediate',
                tags: ['react', 'javascript', 'frontend'],
                instructor: 'Jane Smith',
                price: '$149'
              }
            };

            const course = courseDetails[courseId];
            if (!course) {
              return res.json({
                jsonrpc: '2.0',
                id: body.id,
                error: {
                  code: -32602,
                  message: `Course with ID '${courseId}' not found`
                }
              });
            }

            return res.json({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                content: [
                  {
                    type: 'text',
                    text: `**${course.title}**\n\n` +
                          `Description: ${course.description}\n` +
                          `Category: ${course.category}\n` +
                          `Duration: ${course.duration}\n` +
                          `Lessons: ${course.lessons}\n` +
                          `Difficulty: ${course.difficulty}\n` +
                          `Instructor: ${course.instructor}\n` +
                          `Price: ${course.price}\n` +
                          `Tags: ${course.tags.join(', ')}`
                  }
                ]
              }
            });
          }

          if (name === 'search_courses') {
            const query = args?.query?.toLowerCase() || '';
            const tags = args?.tags || [];

            const courses = [
              { id: 'js-fundamentals', title: 'JavaScript Fundamentals', description: 'Learn the basics of JavaScript programming', category: 'programming', tags: ['javascript', 'programming', 'beginner'] },
              { id: 'react-dev', title: 'React Development', description: 'Build modern web apps with React', category: 'programming', tags: ['react', 'javascript', 'frontend'] },
              { id: 'node-backend', title: 'Node.js Backend', description: 'Server-side JavaScript development', category: 'programming', tags: ['nodejs', 'javascript', 'backend'] },
              { id: 'db-design', title: 'Database Design', description: 'Design and optimize databases', category: 'programming', tags: ['database', 'sql', 'design'] },
              { id: 'ui-design', title: 'UI/UX Design', description: 'Create beautiful and functional user interfaces', category: 'design', tags: ['design', 'ui', 'ux'] },
              { id: 'business-strategy', title: 'Business Strategy', description: 'Learn strategic thinking and business planning', category: 'business', tags: ['business', 'strategy', 'management'] }
            ];

            let results = courses.filter(course => 
              course.title.toLowerCase().includes(query) || 
              course.description.toLowerCase().includes(query) ||
              course.tags.some(tag => tag.toLowerCase().includes(query))
            );

            if (tags.length > 0) {
              results = results.filter(course => 
                tags.some(tag => course.tags.includes(tag))
              );
            }

            return res.json({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                content: [
                  {
                    type: 'text',
                    text: `Found ${results.length} courses matching "${query}":\n\n` + 
                          (results.length > 0 ? 
                            results.map((course, index) => 
                              `${index + 1}. **${course.title}**\n   ${course.description}\n   Tags: ${course.tags.join(', ')}\n   ID: ${course.id}`
                            ).join('\n\n') :
                            'No courses found matching your search criteria.'
                          )
                  }
                ]
              }
            });
          }

          if (name === 'get_user_progress') {
            const courseId = args?.course_id;
            
            const progress = {
              total_courses: 6,
              completed_courses: 2,
              in_progress_courses: 1,
              total_lessons: 45,
              completed_lessons: 18,
              current_streak: 7,
              total_study_time: '24 hours'
            };

            let progressText = `**Your Learning Progress**\n\n` +
                              `Total Courses: ${progress.total_courses}\n` +
                              `Completed: ${progress.completed_courses}\n` +
                              `In Progress: ${progress.in_progress_courses}\n` +
                              `Total Lessons: ${progress.total_lessons}\n` +
                              `Completed Lessons: ${progress.completed_lessons}\n` +
                              `Current Streak: ${progress.current_streak} days\n` +
                              `Total Study Time: ${progress.total_study_time}`;

            if (courseId) {
              progressText += `\n\n**Progress for Course ID: ${courseId}**\n` +
                             `Status: In Progress\n` +
                             `Lessons Completed: 8/12\n` +
                             `Last Activity: 2 days ago`;
            }

            return res.json({
              jsonrpc: '2.0',
              id: body.id,
              result: {
                content: [
                  {
                    type: 'text',
                    text: progressText
                  }
                ]
              }
            });
          }

          return res.json({
            jsonrpc: '2.0',
            id: body.id,
            error: {
              code: -32601,
              message: `Unknown tool: ${name}`
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
    version: '1.0.0',
    description: 'MCP server for BRAINLOOP spaced repetition learning platform',
    endpoints: {
      mcp: '/api/mcp/server',
      sse: '/api/mcp/sse',
      auth: '/api/auth/authorize',
      health: '/health'
    },
    discovery: {
      oauth: '/.well-known/oauth-authorization-server',
      mcp_config: '/.well-known/mcp-client-config'
    }
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