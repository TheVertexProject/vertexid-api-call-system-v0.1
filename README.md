# Vertex ID API v0.1

Cloudflare Worker API for the Vertex ID prototype.

## Important

- Keep this GitHub repository PRIVATE.
- Never commit `.env`, Turso tokens, JWT secrets, Google OAuth secrets, or other credentials.
- The Electron app should call this API. It must NOT connect directly to Turso.

## Endpoints

GET  /api/health
POST /api/auth/register
POST /api/auth/login
GET  /api/auth/me

## Deploy

Install Node.js first, then:

```bash
npm install
npx wrangler login
npx wrangler secret put TURSO_DATABASE_URL
npx wrangler secret put TURSO_AUTH_TOKEN
npx wrangler secret put JWT_SECRET
npm run deploy
```

Use your real Turso values only when Wrangler asks for them.

## Example registration

```json
{
  "vertexId": "demo@vertex.jo3.org",
  "password": "use-a-test-password"
}
```

## Example login

```json
{
  "vertexId": "demo@vertex.jo3.org",
  "password": "use-a-test-password"
}
```

This is a development foundation, not a production-ready identity provider. Before real users are allowed to register, add rate limiting, email/account verification, abuse protection, password reset, session revocation, logging policy, and a privacy policy.
