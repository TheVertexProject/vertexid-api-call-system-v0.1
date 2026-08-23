const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

function normalizeVertexId(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidVertexId(id) {
  return /^[a-z0-9._-]{3,32}@vertex\.jo3\.org$/.test(id);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  return crypto.subtle.digest("SHA-256", data);
}

async function hashPassword(password, saltBytes = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 120000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    salt: bytesToBase64Url(saltBytes),
    hash: bytesToBase64Url(new Uint8Array(bits))
  };
}

async function verifyPassword(password, salt, expectedHash) {
  const saltBytes = base64UrlToBytes(salt);
  const result = await hashPassword(password, saltBytes);
  const a = result.hash;
  const b = expectedHash;

  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
}

async function createToken(vertexId, secret) {
  const header = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const payload = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({
    sub: vertexId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
  })));
  const unsigned = `${header}.${payload}`;
  const signature = bytesToBase64Url(await hmac(secret, unsigned));
  return `${unsigned}.${signature}`;
}

async function verifyToken(token, secret) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;

  const [header, payload, signature] = parts;
  const expected = bytesToBase64Url(await hmac(secret, `${header}.${payload}`));
  if (signature !== expected) return null;

  try {
    const data = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payload)));
    if (!data.sub || !data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
    return data;
  } catch {
    return null;
  }
}

function tursoUrl(databaseUrl) {
  return databaseUrl.replace(/^libsql:\/\//, "https://").replace(/^https:\/\//, "https://");
}

async function tursoQuery(env, sql, args = []) {
  const url = tursoUrl(env.TURSO_DATABASE_URL);
  const response = await fetch(`${url}/v2/pipeline`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${env.TURSO_AUTH_TOKEN}`,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      requests: [
        {
          type: "execute",
          stmt: { sql, args: args.map(value => ({ type: typeof value === "number" ? "integer" : "text", value: String(value) })) }
        },
        { type: "close" }
      ]
    })
  });

  if (!response.ok) {
    throw new Error(`Turso HTTP ${response.status}`);
  }

  const data = await response.json();
  const result = data.results?.[0];

  if (result?.type === "error") {
    throw new Error(result.error?.message || "Turso query failed");
  }

  return result?.response?.result || result?.result || {};
}

async function ensureSchema(env) {
  await tursoQuery(env, `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vertex_id TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active'
    )
  `);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function register(request, env) {
  const body = await readJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400);

  const vertexId = normalizeVertexId(body.vertexId);
  const password = String(body.password || "");

  if (!isValidVertexId(vertexId)) {
    return json({ error: "Vertex ID must look like username@vertex.jo3.org" }, 400);
  }

  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
  }

  const passwordData = await hashPassword(password);

  try {
    await tursoQuery(
      env,
      `INSERT INTO users (vertex_id, password_hash, password_salt, created_at)
       VALUES (?, ?, ?, ?)`,
      [vertexId, passwordData.hash, passwordData.salt, new Date().toISOString()]
    );

    const token = await createToken(vertexId, env.JWT_SECRET);

    return json({
      success: true,
      vertexId,
      token
    }, 201);
  } catch (error) {
    if (String(error.message).toLowerCase().includes("unique")) {
      return json({ error: "Vertex ID already exists" }, 409);
    }
    console.error(error);
    return json({ error: "Database operation failed" }, 500);
  }
}

async function login(request, env) {
  const body = await readJson(request);
  if (!body) return json({ error: "Invalid JSON" }, 400);

  const vertexId = normalizeVertexId(body.vertexId);
  const password = String(body.password || "");

  if (!isValidVertexId(vertexId) || !password) {
    return json({ error: "Invalid credentials" }, 401);
  }

  try {
    const result = await tursoQuery(
      env,
      `SELECT vertex_id, password_hash, password_salt, status
       FROM users WHERE vertex_id = ? LIMIT 1`,
      [vertexId]
    );

    const rows = result.rows || [];
    if (!rows.length) return json({ error: "Invalid credentials" }, 401);

    const row = rows[0];
    const values = row.values || row;
    const storedId = values[0]?.value ?? values[0];
    const storedHash = values[1]?.value ?? values[1];
    const storedSalt = values[2]?.value ?? values[2];
    const status = values[3]?.value ?? values[3];

    if (status !== "active" || !(await verifyPassword(password, storedSalt, storedHash))) {
      return json({ error: "Invalid credentials" }, 401);
    }

    const token = await createToken(storedId, env.JWT_SECRET);
    return json({ success: true, vertexId: storedId, token });
  } catch (error) {
    console.error(error);
    return json({ error: "Database operation failed" }, 500);
  }
}

async function me(request, env) {
  const authorization = request.headers.get("authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  const claims = await verifyToken(token, env.JWT_SECRET);
  if (!claims) return json({ error: "Unauthorized" }, 401);

  return json({
    success: true,
    vertexId: claims.sub
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: JSON_HEADERS });
    }

    const url = new URL(request.url);

    try {
      if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN || !env.JWT_SECRET) {
        return json({ error: "Server configuration is incomplete" }, 500);
      }

      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({ status: "ok", service: "vertexid-api", version: "0.1.0" });
      }

      if (url.pathname === "/api/auth/register" && request.method === "POST") {
        await ensureSchema(env);
        return register(request, env);
      }

      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        return login(request, env);
      }

      if (url.pathname === "/api/auth/me" && request.method === "GET") {
        return me(request, env);
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error(error);
      return json({ error: "Internal server error" }, 500);
    }
  }
};
