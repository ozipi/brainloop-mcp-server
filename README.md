# BRAINLOOP MCP Server

Minimal Model Context Protocol (MCP) server for BRAINLOOP spaced repetition learning platform.

## Features

- OAuth2 Authorization Server Discovery (RFC 8414)
- Server-Sent Events (SSE) streaming for Claude web interface
- MCP JSON-RPC 2.0 protocol support
- JWT authentication and authorization
- Claude web detection and integration
- Health check endpoint for monitoring

## Endpoints

- `/.well-known/oauth-authorization-server` - OAuth2 discovery
- `/.well-known/mcp-client-config` - MCP client configuration
- `/api/mcp/sse` - SSE streaming for Claude web
- `/api/mcp/server` - Main MCP server endpoint
- `/api/auth/authorize` - OAuth authorization
- `/api/auth/token` - OAuth token exchange
- `/health` - Health check

## Deployment

This server is designed for deployment on Railway with Docker.

### Environment Variables

```bash
NEXTAUTH_SECRET=your-jwt-secret
NEXTAUTH_URL=https://mcp.brainloop.cc
DATABASE_URL=your-database-url
PORT=3000
```

### Local Development

```bash
npm install
npm start
```

## Architecture

This is a lightweight Express.js server containing only MCP-related functionality, separate from the main BRAINLOOP Next.js application.