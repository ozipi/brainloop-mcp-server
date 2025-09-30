const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

// Version info
const SERVER_VERSION = '3.0.18';
console.log(`🚀 BRAINLOOP MCP Server v${SERVER_VERSION} starting...`);

// Global Prisma instance
const prisma = new PrismaClient();

const JWT_SECRET = process.env.NEXTAUTH_SECRET || 'your-jwt-secret';

// In-memory stores for OAuth flow (in production, use Redis or database)
const authorizationCodes = new Map(); // code -> { clientId, userId, scopes, expiresAt }
const refreshTokens = new Map(); // token -> { clientId, userId, scopes, expiresAt }

// Default OAuth client for MCP
const MCP_CLIENT = {
  id: 'brainloop-mcp-client',
  secret: 'mcp-client-secret', // In production, this should be properly secured
  name: 'BRAINLOOP MCP Client',
  redirectUris: ['https://claude.ai/api/mcp/auth_callback']
};

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: '*',
  credentials: true
}));

// Enhanced logging middleware
app.use((req, res, next) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  const origin = req.headers.origin || 'no-origin';
  const authHeader = req.headers.authorization || 'no-auth';

  // Log ALL requests to see what Claude is trying to access
  console.log(`🔍 [${req.method}] ${req.path}`, {
    userAgent: userAgent.substring(0, 100),
    origin,
    hasAuth: authHeader !== 'no-auth',
    referer: req.headers.referer || 'none',
    query: Object.keys(req.query).length ? req.query : 'none',
    timestamp: new Date().toISOString()
  });

  next();
});

// GET root endpoint with SSE support for authenticated MCP connection
// This is what Claude calls AFTER OAuth: GET / with Accept: text/event-stream and Authorization: Bearer
app.get('/', async (req, res) => {
  const acceptHeader = req.headers.accept || '';
  const authHeader = req.headers.authorization || '';

  console.log('🔍 [GET] Root request:', {
    accept: acceptHeader,
    hasAuth: !!authHeader,
    userAgent: req.headers['user-agent']?.substring(0, 50) || 'unknown',
    isSSERequest: acceptHeader.includes('text/event-stream'),
    timestamp: new Date().toISOString()
  });

  // Check if Claude is requesting SSE connection
  if (acceptHeader.includes('text/event-stream')) {
    // This is the SSE connection Claude makes AFTER OAuth
    const authContext = await authenticateRequest(req);

    if (!authContext) {
      console.log('❌ SSE connection failed: No valid authentication');
      const baseUrl = "https://mcp.brainloop.cc";
      res.set('WWW-Authenticate', `Bearer realm="MCP", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
      return res.status(401).json({
        error: "unauthorized",
        error_description: "Authentication required for MCP connection"
      });
    }

    console.log('✅ Authenticated SSE connection established for user:', authContext.userId);

    // Set up Server-Sent Events
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type'
    });

    // Send initial connection success
    res.write('event: connected\n');
    res.write(`data: {"status": "connected", "userId": "${authContext.userId}", "timestamp": "${new Date().toISOString()}"}\n\n`);

    // Keep connection alive
    const keepAlive = setInterval(() => {
      res.write('event: ping\n');
      res.write(`data: {"type": "ping", "timestamp": "${new Date().toISOString()}"}\n\n`);
    }, 30000);

    // Handle client disconnect
    req.on('close', () => {
      console.log('📡 SSE connection closed for user:', authContext.userId);
      clearInterval(keepAlive);
    });

    return;
  }

  // Regular GET request (not SSE)
  res.json({
    status: 'BRAINLOOP MCP Server Ready',
    version: SERVER_VERSION,
    timestamp: new Date().toISOString(),
    message: 'Use Accept: text/event-stream with Bearer token for MCP connection'
  });
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
    console.log("❌ No valid Bearer token found");
    return null;
  }

  const token = authHeader.substring(7);

  console.log("🎫 Token received:", {
    tokenLength: token.length,
    tokenStart: token.substring(0, 20) + "..."
  });

  try {
    // Verify JWT token issued by main BRAINLOOP app
    const decoded = jwt.verify(token, JWT_SECRET);

    console.log("✅ Token decoded successfully:", {
      sub: decoded.sub,
      aud: decoded.aud,
      scope: decoded.scope,
      exp: decoded.exp,
      iat: decoded.iat
    });

    // Validate that the token has proper MCP scopes
    const scopes = decoded.scope ? decoded.scope.split(' ') : [];
    const hasValidScope = scopes.some(scope =>
      scope.startsWith('mcp:') || scope === 'claudeai'
    );

    console.log("🔍 Scope validation:", {
      scopes,
      hasValidScope,
      acceptedScopes: ["mcp:read", "mcp:write", "claudeai"]
    });

    if (!hasValidScope) {
      console.log('❌ Token missing required MCP scopes');
      return null;
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.sub }
    });

    if (!user) {
      console.log('❌ User not found in database');
      return null;
    }

    console.log("✅ User authenticated successfully:", {
      userId: user.id,
      email: user.email,
      name: user.name
    });

    return {
      isAuthenticated: true,
      userId: decoded.sub,
      clientId: decoded.aud,
      scopes: scopes,
      resources: ['*'],
      audience: ['mcp-server'],
    };
  } catch (error) {
    console.log("❌ Token verification failed:", {
      error: error.message,
      tokenStart: token.substring(0, 20) + "..."
    });
    return null;
  }
}

// Remove OAuth discovery - OAuth is handled by main BRAINLOOP app

// MCP Client Configuration Discovery removed - handled by main BRAINLOOP app

// Removed MCP client config - let Claude discover OAuth naturally through standard OAuth discovery

// OAuth2 Protected Resource Discovery (RFC 8707)
app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const baseUrl = "https://mcp.brainloop.cc";

  console.log('🛡️ OAuth Protected Resource Discovery Request:', {
    userAgent: req.headers['user-agent']?.substring(0, 80) || 'unknown',
    referer: req.headers.referer || 'none',
    timestamp: new Date().toISOString()
  });

  const config = {
    // Standard OAuth2 Protected Resource metadata
    resource_identifier: baseUrl,
    authorization_servers: [baseUrl],
    scopes_supported: [
      'mcp:read',
      'mcp:courses:read',
      'mcp:courses:write'
    ],
    bearer_methods_supported: ['header'],
    resource_documentation: `${baseUrl}/.well-known/oauth-authorization-server`,

    // MCP-specific protected resource information
    mcp_endpoints: {
      server: `${baseUrl}/api/mcp/server`,
      sse: `${baseUrl}/api/mcp/sse`
    },
    mcp_protocol_version: '2024-11-05',
    mcp_capabilities: {
      tools: { listChanged: true },
      resources: { listChanged: true, subscribe: false },
      logging: { level: 'info' }
    },

    // Claude-specific indicators
    supports_claude_web: true,
    mcp_ready: true
  };

  console.log('📤 OAuth Protected Resource Response:', {
    resource_identifier: config.resource_identifier,
    mcp_endpoints: config.mcp_endpoints,
    supports_claude_web: config.supports_claude_web
  });

  res.set({
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-MCP-Protocol-Version': '2024-11-05',
    'X-MCP-Server-Name': 'BRAINLOOP',
    'X-MCP-Capabilities': 'tools,resources',
    'X-Supports-Claude-Web': 'true'
  });

  res.json(config);
});

// OAuth2 Authorization Server Discovery (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const baseUrl = "https://mcp.brainloop.cc";

  console.log('🔍 OAuth Discovery Request from:', {
    userAgent: req.headers['user-agent']?.substring(0, 80) || 'unknown',
    referer: req.headers.referer || 'none',
    timestamp: new Date().toISOString()
  });

  const config = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    grant_types_supported: [
      'authorization_code',
      'client_credentials'
    ],
    code_challenge_methods_supported: ['S256']
  };

  console.log('📤 Simplified OAuth Discovery Response:', {
    authorization_endpoint: config.authorization_endpoint,
    token_endpoint: config.token_endpoint,
    issuer: config.issuer
  });

  res.set({
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'X-MCP-Protocol-Version': '2024-11-05',
    'X-MCP-Server-Name': 'BRAINLOOP',
    'X-MCP-Capabilities': 'tools,resources',
    'X-Supports-Claude-Web': 'true'
  });

  res.json(config);
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
          version: '3.0.0',
          description: 'Self-contained MCP server for BRAINLOOP spaced repetition learning platform'
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

// OAuth authorization endpoint - self-contained
app.get("/oauth/authorize", (req, res) => {
  const { response_type, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;

  console.log("🔐 Self-contained OAuth authorize request:", {
    response_type, client_id, redirect_uri, scope, state,
    hasCodeChallenge: !!code_challenge,
    codeChallengeMethod: code_challenge_method,
    allParams: req.query
  });

  // Check for missing parameters and provide helpful errors
  if (!response_type) {
    console.log("❌ Missing response_type parameter");
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing response_type parameter"
    });
  }

  if (!client_id) {
    console.log("❌ Missing client_id parameter");
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing client_id parameter"
    });
  }

  if (!redirect_uri) {
    console.log("❌ Missing redirect_uri parameter");
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing redirect_uri parameter"
    });
  }

  // Validate request parameters
  if (response_type !== "code") {
    console.log("❌ Unsupported response_type:", response_type);
    const errorUrl = `${redirect_uri}?error=unsupported_response_type&state=${state}`;
    return res.redirect(errorUrl);
  }

  // Accept any client_id (following working repo pattern)
  console.log("✅ Accepting client_id:", client_id);

  // Accept Claude's redirect_uri (following working repo pattern)
  if (!redirect_uri.includes('claude.ai')) {
    console.log("❌ Invalid redirect_uri - must be claude.ai:", redirect_uri);
    return res.status(400).json({ error: "invalid_redirect_uri" });
  }

  // Check if user is authenticated with BRAINLOOP via Google OAuth
  if (!req.query.approve && !req.query.code) {
    // Build Google OAuth URL for BRAINLOOP authentication
    const googleOAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
      `client_id=${process.env.GOOGLE_CLIENT_ID}&` +
      `redirect_uri=${encodeURIComponent('https://mcp.brainloop.cc/oauth/google/callback')}&` +
      `response_type=code&` +
      `scope=${encodeURIComponent('openid email profile')}&` +
      `state=${encodeURIComponent(JSON.stringify({
        original_client_id: client_id,
        original_redirect_uri: redirect_uri,
        original_state: state,
        original_code_challenge: code_challenge,
        original_code_challenge_method: code_challenge_method,
        original_scope: scope,
        original_response_type: response_type
      }))}`;

    // Show Google OAuth consent page
    const googleConsentPage = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>BRAINLOOP MCP Authorization</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; margin-bottom: 20px; }
        .app-info { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .permissions { margin: 20px 0; }
        .permission { padding: 8px 0; border-bottom: 1px solid #eee; }
        .buttons { margin-top: 30px; text-align: center; }
        .google-btn {
          background: #4285f4;
          color: white;
          padding: 12px 30px;
          margin: 0 10px;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 16px;
          text-decoration: none;
          display: inline-block;
        }
        .deny { background: #6c757d; color: white; padding: 12px 30px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover, .google-btn:hover { opacity: 0.9; }
        .google-logo { width: 18px; height: 18px; margin-right: 8px; vertical-align: middle; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>🔐 BRAINLOOP Authorization</h1>

        <div class="app-info">
          <strong>Claude AI</strong> wants to connect to your BRAINLOOP account.
        </div>

        <div class="permissions">
          <h3>Requested Permissions:</h3>
          <div class="permission">📖 Read your course progress</div>
          <div class="permission">📚 Access your course materials</div>
          <div class="permission">✏️ Update your learning progress</div>
        </div>

        <p>Please sign in with your BRAINLOOP account (Google) to authorize Claude AI access:</p>

        <div class="buttons">
          <a href="${googleOAuthUrl}" class="google-btn">
            <svg class="google-logo" viewBox="0 0 24 24">
              <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Sign in with Google
          </a>
          <button type="button" class="deny" onclick="deny()">❌ Cancel</button>
        </div>
      </div>

      <script>
        function deny() {
          const url = '${redirect_uri}?error=access_denied&state=${state}';
          window.location.href = url;
        }
      </script>
    </body>
    </html>
    `;

    return res.send(googleConsentPage);
  }

  // If we reach here, it means the user is coming back from Google OAuth
  // This shouldn't happen in the new flow, as Google OAuth callback handles everything
  console.log("⚠️ Unexpected path in OAuth authorize - user should go through Google OAuth");
  const errorUrl = `${redirect_uri}?error=access_denied&error_description=Authentication%20required&state=${state}`;
  return res.redirect(errorUrl);
});

// Google OAuth callback handler
app.get("/oauth/google/callback", async (req, res) => {
  const { code, state } = req.query;

  console.log("🔍 Google OAuth callback received:", {
    hasCode: !!code,
    hasState: !!state,
    codePreview: code ? code.substring(0, 20) + '...' : 'none'
  });

  if (!code || !state) {
    console.log("❌ Missing code or state in Google OAuth callback");
    return res.status(400).send("Missing authorization code or state");
  }

  try {
    // Parse the original OAuth parameters from state
    const originalParams = JSON.parse(state);
    console.log("📋 Original OAuth parameters:", {
      client_id: originalParams.original_client_id,
      redirect_uri: originalParams.original_redirect_uri,
      state: originalParams.original_state
    });

    // Exchange Google authorization code for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: 'https://mcp.brainloop.cc/oauth/google/callback'
      })
    });

    const tokenData = await tokenResponse.json();
    console.log("🎫 Google token exchange:", {
      success: !!tokenData.access_token,
      hasIdToken: !!tokenData.id_token
    });

    if (!tokenData.access_token) {
      console.log("❌ Failed to get Google access token:", tokenData);
      const errorUrl = `${originalParams.original_redirect_uri}?error=server_error&state=${originalParams.original_state}`;
      return res.redirect(errorUrl);
    }

    // Get user info from Google
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });

    const googleUser = await userResponse.json();
    console.log("👤 Google user info:", {
      email: googleUser.email,
      name: googleUser.name,
      verified: googleUser.verified_email
    });

    // Find user in BRAINLOOP database
    const brainloopUser = await prisma.user.findUnique({
      where: { email: googleUser.email }
    });

    if (!brainloopUser) {
      console.log("❌ User not found in BRAINLOOP database:", googleUser.email);
      const errorUrl = `${originalParams.original_redirect_uri}?error=access_denied&error_description=User%20not%20found&state=${originalParams.original_state}`;
      return res.redirect(errorUrl);
    }

    console.log("✅ BRAINLOOP user authenticated:", {
      userId: brainloopUser.id,
      email: brainloopUser.email
    });

    // Generate authorization code for Claude
    const authCode = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Store authorization code with authenticated user
    authorizationCodes.set(authCode, {
      clientId: originalParams.original_client_id,
      userId: brainloopUser.id, // Use actual BRAINLOOP user ID
      scopes: originalParams.original_scope ? originalParams.original_scope.split(' ') : ['claudeai'],
      redirectUri: originalParams.original_redirect_uri,
      codeChallenge: originalParams.original_code_challenge,
      codeChallengeMethod: originalParams.original_code_challenge_method,
      expiresAt
    });

    console.log("✅ Authorization code generated for BRAINLOOP user:", {
      code: authCode.substring(0, 10) + '...',
      userId: brainloopUser.id,
      email: brainloopUser.email,
      clientId: originalParams.original_client_id
    });

    // Redirect back to Claude with authorization code
    const redirectUrl = `${originalParams.original_redirect_uri}?code=${authCode}&state=${originalParams.original_state}`;
    console.log("🚀 Redirecting to Claude with auth code:", {
      redirectUri: originalParams.original_redirect_uri,
      codePreview: authCode.substring(0, 20) + '...',
      state: originalParams.original_state
    });

    res.redirect(redirectUrl);

  } catch (error) {
    console.error("❌ Error in Google OAuth callback:", error);
    const originalParams = JSON.parse(state);
    const errorUrl = `${originalParams.original_redirect_uri}?error=server_error&state=${originalParams.original_state}`;
    res.redirect(errorUrl);
  }
});

// OAuth Dynamic Client Registration (RFC 7591) - Required by Claude
app.post("/oauth/register", (req, res) => {
  const { redirect_uris, client_name, token_endpoint_auth_method, grant_types, response_types, scope } = req.body;

  console.log("📋 Dynamic Client Registration request:", {
    client_name,
    redirect_uris,
    token_endpoint_auth_method,
    grant_types,
    response_types,
    scope,
    userAgent: req.headers['user-agent']?.substring(0, 80) || 'unknown',
    timestamp: new Date().toISOString()
  });

  // Validate required fields
  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uris is required and must be an array"
    });
  }

  // Validate Claude's expected redirect URI
  const validRedirectUris = redirect_uris.filter(uri =>
    uri === 'https://claude.ai/api/mcp/auth_callback' ||
    uri.startsWith('https://claude.ai/api/mcp/auth_callback')
  );

  if (validRedirectUris.length === 0) {
    return res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uri must be https://claude.ai/api/mcp/auth_callback"
    });
  }

  // Generate client credentials
  const clientId = `brainloop-mcp-${crypto.randomBytes(8).toString('hex')}`;
  const clientSecret = crypto.randomBytes(32).toString('hex');

  console.log("✅ Dynamic client registered:", { clientId, validRedirectUris });

  // Return client registration response per RFC 7591
  res.json({
    client_id: clientId,
    client_secret: clientSecret,
    client_secret_expires_at: 0, // Never expires
    redirect_uris: validRedirectUris,
    client_name: client_name || 'Claude MCP Client',
    token_endpoint_auth_method: token_endpoint_auth_method || 'client_secret_post',
    grant_types: grant_types || ['authorization_code'],
    response_types: response_types || ['code'],
    scope: scope || 'mcp:read mcp:courses:read mcp:courses:write'
  });
});

// OAuth token endpoint - self-contained
app.post("/oauth/token", async (req, res) => {
  const { grant_type, code, client_id, redirect_uri, code_verifier } = req.body;

  console.log("🎫 Self-contained OAuth token request:", {
    grant_type, code: code?.substring(0, 10) + '...', client_id, redirect_uri,
    hasCodeVerifier: !!code_verifier
  });

  // Validate grant type
  if (grant_type !== "authorization_code") {
    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Only authorization_code grant type is supported"
    });
  }

  // Validate authorization code
  if (!code || !authorizationCodes.has(code)) {
    console.log("❌ Invalid or expired authorization code");
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code is invalid or expired"
    });
  }

  const authData = authorizationCodes.get(code);

  // Check if code is expired
  if (Date.now() > authData.expiresAt) {
    authorizationCodes.delete(code);
    console.log("❌ Authorization code expired");
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has expired"
    });
  }

  // Validate client
  if (client_id !== authData.clientId) {
    console.log("❌ Client ID mismatch");
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match"
    });
  }

  // Validate redirect URI
  if (redirect_uri !== authData.redirectUri) {
    console.log("❌ Redirect URI mismatch");
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Redirect URI does not match"
    });
  }

  // Validate PKCE if present
  if (authData.codeChallenge) {
    if (!code_verifier) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Code verifier is required"
      });
    }

    const challengeMethod = authData.codeChallengeMethod || 'S256';
    let computedChallenge;

    if (challengeMethod === 'S256') {
      computedChallenge = crypto.createHash('sha256')
        .update(code_verifier)
        .digest('base64url');
    } else if (challengeMethod === 'plain') {
      computedChallenge = code_verifier;
    }

    if (computedChallenge !== authData.codeChallenge) {
      console.log("❌ PKCE validation failed");
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "Code verifier is invalid"
      });
    }
  }

  // Generate access token
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = 3600; // 1 hour
  const accessToken = jwt.sign(
    {
      iss: 'https://mcp.brainloop.cc',
      sub: authData.userId,
      aud: client_id,
      scope: authData.scopes.join(' '),
      iat: now,
      exp: now + expiresIn
    },
    JWT_SECRET
  );

  // Generate refresh token
  const refreshToken = crypto.randomBytes(32).toString('hex');
  refreshTokens.set(refreshToken, {
    clientId: client_id,
    userId: authData.userId,
    scopes: authData.scopes,
    expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000) // 30 days
  });

  // Remove authorization code (one-time use)
  authorizationCodes.delete(code);

  console.log("✅ Access token generated successfully:", {
    sub: authData.userId,
    clientId: client_id,
    scopes: authData.scopes,
    expiresIn,
    tokenPreview: accessToken.substring(0, 20) + '...'
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn,
    refresh_token: refreshToken,
    scope: authData.scopes.join(' ')
  });
});

// OAuth userinfo endpoint - self-contained
app.get("/oauth/userinfo", async (req, res) => {
  console.log("👤 Self-contained userinfo request received");

  try {
    const authContext = await authenticateRequest(req);
    if (!authContext) {
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Access token is invalid or expired"
      });
    }

    console.log("✅ Userinfo for authenticated user:", authContext.userId);

    // For MCP clients, return a generic user profile
    // In a real implementation, you'd fetch from database
    res.json({
      sub: authContext.userId,
      name: "MCP User",
      email: "mcp@brainloop.cc",
      picture: null,
      email_verified: true,
      scope: authContext.scopes.join(' ')
    });
  } catch (error) {
    console.error("❌ Userinfo error:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error"
    });
  }
});

app.get("/.well-known/jwks.json", (req, res) => {
  console.log("🔑 JWKS request received");
  res.json({ keys: [] });
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

    // Allow Claude web to perform notifications/initialized without authentication, but NOT initialize
    if (isClaudeWeb && method === 'notifications/initialized') {
      console.log('🔓 Allowing Claude web discovery call without auth:', method);

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
      console.log('❌ MCP Server: Authentication required - sending WWW-Authenticate header');
      const baseUrl = "https://mcp.brainloop.cc";
      res.set('WWW-Authenticate', `Bearer realm="MCP", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
      return res.status(401).json({
        jsonrpc: '2.0',
        id: body.id,
        error: { code: -32001, message: 'Authentication required' }
      });
    }

    console.log('✅ Authenticated MCP request for user:', authContext.userId);

    // Handle authenticated MCP methods here
    if (method === 'initialize') {
      console.log('🔄 Authenticated MCP initialize request');
      return res.json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          protocolVersion: '2025-06-18',
          capabilities: {
            tools: {},
            resources: {},
            logging: { level: 'info' }
          },
          serverInfo: {
            name: 'BRAINLOOP MCP Server',
            version: '3.0.23',
            description: 'Personalized learning data access for BRAINLOOP users'
          },
          tools: [
            {
              name: 'create_course',
              description: 'Create a new course in the BRAINLOOP system',
              inputSchema: {
                type: 'object',
                properties: {
                  title: { type: 'string', description: 'Course title' },
                  description: { type: 'string', description: 'Course description' },
                  author: { type: 'string', description: 'Course author' }
                },
                required: ['title', 'description']
              }
            },
            {
              name: 'get_user_progress',
              description: 'Get learning progress for the authenticated user',
              inputSchema: {
                type: 'object',
                properties: {
                  courseId: { type: 'string', description: 'Optional course ID to filter by' }
                }
              }
            },
            {
              name: 'get_user_enrollments',
              description: 'Get all courses the user is enrolled in',
              inputSchema: {
                type: 'object',
                properties: {}
              }
            }
          ]
        }
      });
    }

    if (method === 'tools/list') {
      console.log('🔧 Authenticated tools/list request');
      return res.json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          tools: [
            {
              name: 'get_courses',
              description: 'Get list of available courses for the authenticated user',
              inputSchema: {
                type: 'object',
                properties: {}
              }
            },
            {
              name: 'get_user_progress',
              description: 'Get learning progress for the authenticated user',
              inputSchema: {
                type: 'object',
                properties: {
                  courseId: { type: 'string', description: 'Optional course ID to filter by' }
                }
              }
            },
            {
              name: 'get_user_enrollments',
              description: 'Get all courses the authenticated user is enrolled in',
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
      console.log('📚 Authenticated resources/list request');
      return res.json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          resources: [
            {
              uri: `brainloop://user/${authContext.userId}/courses`,
              name: 'My Courses',
              description: 'Your enrolled courses and progress',
              mimeType: 'application/json'
            },
            {
              uri: `brainloop://user/${authContext.userId}/progress`,
              name: 'Learning Progress',
              description: 'Your learning progress across all courses',
              mimeType: 'application/json'
            }
          ]
        }
      });
    }

    if (method === 'tools/call') {
      const toolName = body.params?.name;
      console.log('🛠️ Authenticated tool call:', toolName);

      if (toolName === 'get_courses') {
        // Get courses for the authenticated user
        const userCourses = await prisma.enrollment.findMany({
          where: { userId: authContext.userId },
          include: {
            course: true,
            progress: true
          }
        });

        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  courses: userCourses.map(enrollment => ({
                    id: enrollment.course.id,
                    title: enrollment.course.title,
                    description: enrollment.course.description,
                    progress: enrollment.progress.length,
                    enrolledAt: enrollment.createdAt
                  }))
                }, null, 2)
              }
            ]
          }
        });
      }

      if (toolName === 'get_user_progress') {
        // Get progress for the authenticated user
        const userProgress = await prisma.progress.findMany({
          where: { userId: authContext.userId },
          include: {
            unit: {
              include: { course: true }
            }
          }
        });

        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  progress: userProgress.map(p => ({
                    courseTitle: p.unit.course.title,
                    unitTitle: p.unit.title,
                    stage: p.stage,
                    nextReview: p.nextReview,
                    lastReviewed: p.lastReviewed,
                    interval: p.interval
                  }))
                }, null, 2)
              }
            ]
          }
        });
      }

      return res.json({
        jsonrpc: '2.0',
        id: body.id,
        error: { code: -32601, message: `Unknown tool: ${toolName}` }
      });
    }

    // Default response for other methods
    return res.json({
      jsonrpc: '2.0',
      id: body.id,
      result: { status: 'authenticated', method, userId: authContext.userId }
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

      // Handle initialize method with authentication
      if (method === 'initialize') {
        const authContext = await authenticateRequest(req);

        if (!authContext) {
          console.log('❌ MCP Server: Authentication required for initialize - sending WWW-Authenticate header');
          const baseUrl = "https://mcp.brainloop.cc";
          res.set('WWW-Authenticate', `Bearer realm="MCP", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
          return res.status(401).json({
            jsonrpc: '2.0',
            id: body.id,
            error: { code: -32001, message: 'Authentication required' }
          });
        }

        console.log('🔄 Authenticated MCP initialize request for user:', authContext.userId);
        return res.json({
          jsonrpc: '2.0',
          id: body.id,
          result: {
            protocolVersion: '2025-06-18',
            capabilities: {
              tools: {},
              resources: {},
              logging: { level: 'info' }
            },
            serverInfo: {
              name: 'BRAINLOOP MCP Server',
              version: '3.0.23',
              description: 'Personalized learning data access for BRAINLOOP users'
            },
            tools: [
              {
                name: 'create_course',
                description: 'Create a new course in the BRAINLOOP system',
                inputSchema: {
                  type: 'object',
                  properties: {
                    title: { type: 'string', description: 'Course title' },
                    description: { type: 'string', description: 'Course description' },
                    author: { type: 'string', description: 'Course author' }
                  },
                  required: ['title', 'description']
                }
              },
              {
                name: 'get_user_progress',
                description: 'Get learning progress for the authenticated user',
                inputSchema: {
                  type: 'object',
                  properties: {
                    courseId: { type: 'string', description: 'Optional course ID to filter by' }
                  }
                }
              },
              {
                name: 'get_user_enrollments',
                description: 'Get all courses the user is enrolled in',
                inputSchema: {
                  type: 'object',
                  properties: {}
                }
              }
            ]
          }
        });
      }

      // Handle tools/list method with authentication
      if (method === 'tools/list') {
        const authContext = await authenticateRequest(req);

        if (!authContext) {
          console.log('❌ MCP Server: Authentication required for tools/list - sending WWW-Authenticate header');
          const baseUrl = "https://mcp.brainloop.cc";
          res.set('WWW-Authenticate', `Bearer realm="MCP", resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`);
          return res.status(401).json({
            jsonrpc: '2.0',
            id: body.id,
            error: { code: -32001, message: 'Authentication required' }
          });
        }

        console.log('🔧 Authenticated tools/list request for user:', authContext.userId);
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
                name: 'get_user_enrollments',
                description: 'Get all courses a user is enrolled in',
                inputSchema: {
                  type: 'object',
                  properties: {
                    userId: { type: 'string', description: 'User ID' },
                  },
                  required: ['userId'],
                },
              }
            ]
          }
        });
      }

      // Allow Claude web to perform notifications/initialized without authentication, but NOT initialize
      if (isClaudeWeb && method === 'notifications/initialized') {
        console.log('🔓 Allowing Claude web discovery call without auth:', method);

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


    } catch (error) {
      console.error('MCP Server error:', error);
      return res.status(500).json({
        jsonrpc: '2.0',
        id: req.body?.id,
        error: { code: -32603, message: 'Internal error' }
      });
    }
  }
  
  // For other requests, return MCP server info indicating this IS the MCP server
  res.json({
    name: 'BRAINLOOP MCP Server',
    version: '3.0.22',
    description: 'MCP server with OAuth 2.1 authentication for BRAINLOOP learning platform',
    mcp: {
      protocol: 'json-rpc-2.0',
      version: '2025-06-18',
      capabilities: ['tools', 'resources'],
      authentication: 'oauth2'
    },
    endpoints: {
      oauth: '/oauth/authorize',
      token: '/oauth/token',
      discovery: '/.well-known/oauth-authorization-server'
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 BRAINLOOP MCP Server v${SERVER_VERSION} running on port ${port}`);
  console.log(`📡 SSE endpoint: /api/mcp/sse`);
  console.log(`🤖 MCP endpoint: /api/mcp/server`);
  console.log(`🔐 OAuth authorize: /oauth/authorize`);
  console.log(`🎫 OAuth token: /oauth/token`);
  console.log(`👤 OAuth userinfo: /oauth/userinfo`);
  console.log(`🔑 Self-contained OAuth 2.1 authorization server`);
  console.log(`✅ Self-contained MCP server v${SERVER_VERSION} deployed successfully`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await prisma.$disconnect();
  process.exit(0);
});