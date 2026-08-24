const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};

const PBKDF2_ITERATIONS = 100000;
const PBKDF2_BITS = 256;

/* =========================================================
   RESPONSE
========================================================= */

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });
}

/* =========================================================
   VERTEX ID
========================================================= */

function normalizeVertexId(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidVertexId(id) {
  return /^[a-z0-9._-]{3,32}@vertex\.jo3\.org$/.test(id);
}

/* =========================================================
   BASE64URL
========================================================= */

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const base64 = String(value)
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded =
    base64 +
    "=".repeat((4 - (base64.length % 4)) % 4);

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    character => character.charCodeAt(0)
  );
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

async function hashPassword(
  password,
  saltBytes = null
) {
  if (!saltBytes) {
    saltBytes = crypto.getRandomValues(
      new Uint8Array(16)
    );
  }

  const passwordKey =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const derivedBits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passwordKey,
      PBKDF2_BITS
    );

  return {
    salt: bytesToBase64Url(saltBytes),
    hash: bytesToBase64Url(
      new Uint8Array(derivedBits)
    )
  };
}

async function verifyPassword(
  password,
  storedSalt,
  storedHash
) {
  if (
    !password ||
    !storedSalt ||
    !storedHash
  ) {
    return false;
  }

  try {
    const saltBytes =
      base64UrlToBytes(storedSalt);

    const calculated =
      await hashPassword(
        password,
        saltBytes
      );

    const calculatedHash =
      calculated.hash;

    const expectedHash =
      String(storedHash);

    if (
      calculatedHash.length !==
      expectedHash.length
    ) {
      return false;
    }

    let difference = 0;

    for (
      let i = 0;
      i < calculatedHash.length;
      i++
    ) {
      difference |=
        calculatedHash.charCodeAt(i) ^
        expectedHash.charCodeAt(i);
    }

    return difference === 0;

  } catch (error) {
    console.error(
      "Password verification failed:",
      error
    );

    return false;
  }
}

/* =========================================================
   JWT
========================================================= */

async function hmac(secret, data) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  return new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    )
  );
}

async function createToken(
  vertexId,
  secret
) {
  const now =
    Math.floor(Date.now() / 1000);

  const header =
    bytesToBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          alg: "HS256",
          typ: "JWT"
        })
      )
    );

  const payload =
    bytesToBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: vertexId,
          iat: now,
          exp: now + 60 * 60 * 24 * 7
        })
      )
    );

  const unsigned =
    `${header}.${payload}`;

  const signature =
    bytesToBase64Url(
      await hmac(
        secret,
        unsigned
      )
    );

  return `${unsigned}.${signature}`;
}

async function verifyToken(
  token,
  secret
) {
  const parts =
    String(token || "").split(".");

  if (parts.length !== 3) {
    return null;
  }

  const [
    header,
    payload,
    signature
  ] = parts;

  const expected =
    bytesToBase64Url(
      await hmac(
        secret,
        `${header}.${payload}`
      )
    );

  if (signature !== expected) {
    return null;
  }

  try {
    const data =
      JSON.parse(
        new TextDecoder().decode(
          base64UrlToBytes(payload)
        )
      );

    const now =
      Math.floor(Date.now() / 1000);

    if (
      !data.sub ||
      !data.exp ||
      data.exp <= now
    ) {
      return null;
    }

    return data;

  } catch {
    return null;
  }
}

/* =========================================================
   TURSO
========================================================= */

function tursoUrl(databaseUrl) {
  return String(databaseUrl)
    .replace(
      /^libsql:\/\//,
      "https://"
    )
    .replace(
      /^https:\/\//,
      "https://"
    );
}

/*
  Turso/libSQL can return values in different
  representations. This function normalizes them.
*/
function extractTursoValue(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  if (
    typeof value === "object"
  ) {
    if (
      Object.prototype.hasOwnProperty.call(
        value,
        "value"
      )
    ) {
      return value.value;
    }

    if (
      Object.prototype.hasOwnProperty.call(
        value,
        "text"
      )
    ) {
      return value.text;
    }

    if (
      Object.prototype.hasOwnProperty.call(
        value,
        "integer"
      )
    ) {
      return value.integer;
    }
  }

  return value;
}

async function tursoQuery(
  env,
  sql,
  args = []
) {
  const databaseUrl =
    env.TURSO_DATABASE_URL;

  if (!databaseUrl) {
    throw new Error(
      "TURSO_DATABASE_URL is missing"
    );
  }

  if (!env.TURSO_AUTH_TOKEN) {
    throw new Error(
      "TURSO_AUTH_TOKEN is missing"
    );
  }

  const url =
    tursoUrl(databaseUrl);

  const response =
    await fetch(
      `${url}/v2/pipeline`,
      {
        method: "POST",

        headers: {
          Authorization:
            `Bearer ${env.TURSO_AUTH_TOKEN}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          requests: [
            {
              type: "execute",

              stmt: {
                sql,

                args:
                  args.map(value => ({
                    type:
                      typeof value ===
                      "number"
                        ? "integer"
                        : "text",

                    value:
                      String(value)
                  }))
              }
            },

            {
              type: "close"
            }
          ]
        })
      }
    );

  if (!response.ok) {
    throw new Error(
      `Turso HTTP ${response.status}`
    );
  }

  const data =
    await response.json();

  const result =
    data.results?.[0];

  if (
    result?.type ===
    "error"
  ) {
    throw new Error(
      result.error?.message ||
      "Turso query failed"
    );
  }

  return (
    result?.response?.result ||
    result?.result ||
    {}
  );
}

/* =========================================================
   DATABASE SCHEMA
========================================================= */

async function ensureSchema(env) {

  await tursoQuery(
    env,
    `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vertex_id TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        recovery_email TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `
  );

  await tursoQuery(
    env,
    `
      CREATE TABLE IF NOT EXISTS cloud_connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        provider_account_id TEXT,
        encrypted_refresh_token TEXT,
        scopes TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id)
          REFERENCES users(id)
      )
    `
  );

  await tursoQuery(
    env,
    `
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_users_vertex_id
      ON users(vertex_id)
    `
  );

  await tursoQuery(
    env,
    `
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_cloud_user_provider
      ON cloud_connections(
        user_id,
        provider
      )
    `
  );
}

/* =========================================================
   REQUEST JSON
========================================================= */

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

/* =========================================================
   REGISTER
========================================================= */

async function register(
  request,
  env
) {
  const body =
    await readJson(request);

  if (!body) {
    return json(
      {
        error:
          "Invalid JSON"
      },
      400
    );
  }

  const vertexId =
    normalizeVertexId(
      body.vertexId
    );

  const password =
    String(
      body.password || ""
    );

  const recoveryEmail =
    body.recoveryEmail
      ? String(
          body.recoveryEmail
        ).trim()
      : null;

  if (
    !isValidVertexId(
      vertexId
    )
  ) {
    return json(
      {
        error:
          "Vertex ID must look like username@vertex.jo3.org"
      },
      400
    );
  }

  if (
    password.length < 8
  ) {
    return json(
      {
        error:
          "Password must be at least 8 characters"
      },
      400
    );
  }

  const passwordData =
    await hashPassword(
      password
    );

  try {

    await tursoQuery(
      env,
      `
        INSERT INTO users (
          vertex_id,
          password_hash,
          password_salt,
          recovery_email,
          status
        )
        VALUES (
          ?,
          ?,
          ?,
          ?,
          'active'
        )
      `,
      [
        vertexId,
        passwordData.hash,
        passwordData.salt,
        recoveryEmail
      ]
    );

    const token =
      await createToken(
        vertexId,
        env.JWT_SECRET
      );

    return json(
      {
        success: true,
        vertexId,
        token
      },
      201
    );

  } catch (error) {

    if (
      String(error.message)
        .toLowerCase()
        .includes("unique")
    ) {
      return json(
        {
          error:
            "Vertex ID already exists"
        },
        409
      );
    }

    console.error(
      "Registration error:",
      error
    );

    return json(
      {
        error:
          "Database operation failed"
      },
      500
    );
  }
}

/* =========================================================
   LOGIN
========================================================= */

async function login(
  request,
  env
) {
  const body =
    await readJson(request);

  if (!body) {
    return json(
      {
        error:
          "Invalid JSON"
      },
      400
    );
  }

  const vertexId =
    normalizeVertexId(
      body.vertexId
    );

  const password =
    String(
      body.password || ""
    );

  if (
    !isValidVertexId(
      vertexId
    ) ||
    !password
  ) {
    return json(
      {
        error:
          "Invalid credentials"
      },
      401
    );
  }

  try {

    const result =
      await tursoQuery(
        env,
        `
          SELECT
            vertex_id,
            password_hash,
            password_salt,
            status
          FROM users
          WHERE vertex_id = ?
          LIMIT 1
        `,
        [vertexId]
      );

    const rows =
      Array.isArray(
        result.rows
      )
        ? result.rows
        : [];

    if (
      rows.length === 0
    ) {
      console.log(
        "Login user not found:",
        vertexId
      );

      return json(
        {
          error:
            "Invalid credentials"
        },
        401
      );
    }

    /*
      IMPORTANT:
      Turso/libSQL result rows are
      normally:

      {
        values: [
          {...},
          {...},
          {...},
          {...}
        ]
      }

      But some responses may provide
      the array directly.
    */

    const rawRow =
      rows[0];

    let values;

    if (
      Array.isArray(rawRow)
    ) {
      values = rawRow;

    } else if (
      rawRow &&
      Array.isArray(
        rawRow.values
      )
    ) {
      values =
        rawRow.values;

    } else {
      values = [];
    }

    const storedId =
      extractTursoValue(
        values[0]
      );

    const storedHash =
      extractTursoValue(
        values[1]
      );

    const storedSalt =
      extractTursoValue(
        values[2]
      );

    const status =
      extractTursoValue(
        values[3]
      );

    console.log({
      loginVertexId:
        vertexId,

      hashLength:
        String(
          storedHash || ""
        ).length,

      saltLength:
        String(
          storedSalt || ""
        ).length,

      status:
        status
    });

    if (
      !storedHash ||
      !storedSalt ||
      status !== "active"
    ) {
      return json(
        {
          error:
            "Invalid credentials"
        },
        401
      );
    }

    const passwordCorrect =
      await verifyPassword(
        password,
        storedSalt,
        storedHash
      );

    if (
      !passwordCorrect
    ) {
      return json(
        {
          error:
            "Invalid credentials"
        },
        401
      );
    }

    const token =
      await createToken(
        storedId ||
          vertexId,
        env.JWT_SECRET
      );

    return json({
      success: true,

      vertexId:
        storedId ||
        vertexId,

      token
    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    return json(
      {
        error:
          "Database operation failed"
      },
      500
    );
  }
}

/* =========================================================
   CURRENT USER
========================================================= */

async function me(
  request,
  env
) {
  const authorization =
    request.headers.get(
      "authorization"
    ) || "";

  const token =
    authorization.startsWith(
      "Bearer "
    )
      ? authorization.slice(7)
      : "";

  if (!token) {
    return json(
      {
        error:
          "Unauthorized"
      },
      401
    );
  }

  const claims =
    await verifyToken(
      token,
      env.JWT_SECRET
    );

  if (!claims) {
    return json(
      {
        error:
          "Unauthorized"
      },
      401
    );
  }

  return json({
    success: true,
    vertexId:
      claims.sub
  });
}

/* =========================================================
   WORKER
========================================================= */

export default {

  async fetch(
    request,
    env
  ) {

    if (
      request.method ===
      "OPTIONS"
    ) {
      return new Response(
        null,
        {
          status: 204,
          headers:
            JSON_HEADERS
        }
      );
    }

    const url =
      new URL(request.url);

    try {

      /*
        Required production secrets.
      */

      if (
        !env.TURSO_DATABASE_URL ||
        !env.TURSO_AUTH_TOKEN ||
        !env.JWT_SECRET
      ) {
        return json(
          {
            error:
              "Server configuration is incomplete"
          },
          500
        );
      }

      /* -----------------------------------------
         HEALTH
      ----------------------------------------- */

      if (
        url.pathname ===
          "/api/health" &&
        request.method ===
          "GET"
      ) {
        return json({
          status:
            "ok",

          service:
            "vertexid-api",

          version:
            "0.2.0"
        });
      }

      /* -----------------------------------------
         REGISTER
      ----------------------------------------- */

      if (
        url.pathname ===
          "/api/auth/register" &&
        request.method ===
          "POST"
      ) {
        await ensureSchema(
          env
        );

        return register(
          request,
          env
        );
      }

      /* -----------------------------------------
         LOGIN
      ----------------------------------------- */

      if (
        url.pathname ===
          "/api/auth/login" &&
        request.method ===
          "POST"
      ) {
        return login(
          request,
          env
        );
      }

      /* -----------------------------------------
         CURRENT USER
      ----------------------------------------- */

      if (
        url.pathname ===
          "/api/auth/me" &&
        request.method ===
          "GET"
      ) {
        return me(
          request,
          env
        );
      }

      /* -----------------------------------------
         NOT FOUND
      ----------------------------------------- */

      return json(
        {
          error:
            "Not found"
        },
        404
      );

    } catch (error) {

      console.error(
        "Worker error:",
        error
      );

      return json(
        {
          error:
            "Internal server error"
        },
        500
      );
    }
  }
};