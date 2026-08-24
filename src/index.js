const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization"
};

const GOOGLE_AUTH_URL =
  "https://accounts.google.com/o/oauth2/v2/auth";

const GOOGLE_TOKEN_URL =
  "https://oauth2.googleapis.com/token";

const GOOGLE_USERINFO_URL =
  "https://openidconnect.googleapis.com/v1/userinfo";

const GOOGLE_PROVIDER =
  "google_drive";

const GOOGLE_REDIRECT_URI =
  "https://vertexid-api-call-system.vedaanranjan83.workers.dev/api/cloud/google/callback";

const GOOGLE_SCOPES = [
  "openid",
  "email",
  "profile",
  "https://www.googleapis.com/auth/drive.file"
].join(" ");

const PBKDF2_ITERATIONS = 100000;


/* =========================================================
   JSON RESPONSE
========================================================= */

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: JSON_HEADERS
    }
  );
}


/* =========================================================
   VERTEX ID
========================================================= */

function normalizeVertexId(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
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
    "=".repeat(
      (4 - (base64.length % 4)) % 4
    );

  const binary = atob(padded);

  return Uint8Array.from(
    binary,
    c => c.charCodeAt(0)
  );
}


/* =========================================================
   PASSWORD HASH
========================================================= */

async function hashPassword(
  password,
  saltBytes = null
) {
  if (!saltBytes) {
    saltBytes =
      crypto.getRandomValues(
        new Uint8Array(16)
      );
  }

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      256
    );

  return {
    salt:
      bytesToBase64Url(
        saltBytes
      ),

    hash:
      bytesToBase64Url(
        new Uint8Array(bits)
      )
  };
}


async function verifyPassword(
  password,
  salt,
  expectedHash
) {
  if (
    !password ||
    !salt ||
    !expectedHash
  ) {
    return false;
  }

  try {
    const result =
      await hashPassword(
        password,
        base64UrlToBytes(
          salt
        )
      );

    const a = result.hash;
    const b = String(
      expectedHash
    );

    if (a.length !== b.length) {
      return false;
    }

    let difference = 0;

    for (
      let i = 0;
      i < a.length;
      i++
    ) {
      difference |=
        a.charCodeAt(i) ^
        b.charCodeAt(i);
    }

    return difference === 0;

  } catch (error) {
    console.error(
      "Password verification error:",
      error
    );

    return false;
  }
}


/* =========================================================
   HMAC / JWT
========================================================= */

async function hmac(
  secret,
  data
) {
  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        secret
      ),
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
      new TextEncoder().encode(
        data
      )
    )
  );
}


async function createToken(
  vertexId,
  secret
) {
  const now =
    Math.floor(
      Date.now() / 1000
    );

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
          exp:
            now +
            60 * 60 * 24 * 7
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
    String(token || "")
      .split(".");

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

  if (
    signature !== expected
  ) {
    return null;
  }

  try {
    const data =
      JSON.parse(
        new TextDecoder().decode(
          base64UrlToBytes(
            payload
          )
        )
      );

    const now =
      Math.floor(
        Date.now() / 1000
      );

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

function tursoUrl(
  databaseUrl
) {
  return String(
    databaseUrl
  )
    .replace(
      /^libsql:\/\//,
      "https://"
    )
    .replace(
      /^https:\/\//,
      "https://"
    );
}


function extractValue(
  value
) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  if (
    typeof value ===
    "object"
  ) {
    if (
      "value" in value
    ) {
      return value.value;
    }
  }

  return value;
}


async function tursoQuery(
  env,
  sql,
  args = []
) {
  const url =
    tursoUrl(
      env.TURSO_DATABASE_URL
    );

  const response =
    await fetch(
      `${url}/v2/pipeline`,
      {
        method: "POST",

        headers: {
          authorization:
            `Bearer ${env.TURSO_AUTH_TOKEN}`,

          "content-type":
            "application/json"
        },

        body:
          JSON.stringify({
            requests: [
              {
                type: "execute",

                stmt: {
                  sql,

                  args:
                    args.map(
                      value => ({
                        type:
                          typeof value ===
                          "number"
                            ? "integer"
                            : "text",

                        value:
                          String(value)
                      })
                    )
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
   DATABASE
========================================================= */

async function ensureSchema(
  env
) {
  await tursoQuery(
    env,
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vertex_id TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active'
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

      encrypted_refresh_token TEXT NOT NULL,

      scopes TEXT,

      status TEXT NOT NULL DEFAULT 'active',

      created_at TEXT NOT NULL,

      updated_at TEXT NOT NULL,

      UNIQUE(user_id, provider),

      FOREIGN KEY(user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    )
    `
  );
}


/* =========================================================
   AUTHENTICATED USER
========================================================= */

async function getAuthenticatedUser(
  request,
  env
) {
  const authorization =
    request.headers.get(
      "authorization"
    ) || "";

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  const token =
    authorization.slice(7);

  return verifyToken(
    token,
    env.JWT_SECRET
  );
}


/* =========================================================
   JSON BODY
========================================================= */

async function readJson(
  request
) {
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
      INSERT INTO users
      (
        vertex_id,
        password_hash,
        password_salt,
        created_at
      )
      VALUES (?, ?, ?, ?)
      `,
      [
        vertexId,
        passwordData.hash,
        passwordData.salt,
        new Date().toISOString()
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

    console.error(error);

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
    await readJson(
      request
    );

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
      result.rows || [];

    if (!rows.length) {
      return json(
        {
          error:
            "Invalid credentials"
        },
        401
      );
    }

    const row =
      rows[0];

    const values =
      row.values ||
      row;

    const storedId =
      extractValue(
        values[0]
      );

    const storedHash =
      extractValue(
        values[1]
      );

    const storedSalt =
      extractValue(
        values[2]
      );

    const status =
      extractValue(
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

      status
    });

    if (
      status !== "active" ||
      !storedHash ||
      !storedSalt
    ) {
      return json(
        {
          error:
            "Invalid credentials"
        },
        401
      );
    }

    const valid =
      await verifyPassword(
        password,
        storedSalt,
        storedHash
      );

    if (!valid) {
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
        storedId,
        env.JWT_SECRET
      );

    return json({
      success: true,
      vertexId: storedId,
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
   ME
========================================================= */

async function me(
  request,
  env
) {
  const claims =
    await getAuthenticatedUser(
      request,
      env
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
   TOKEN ENCRYPTION
========================================================= */

async function getEncryptionKey(
  env
) {
  if (
    !env.TOKEN_ENCRYPTION_KEY
  ) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY is missing"
    );
  }

  const keyBytes =
    base64UrlToBytes(
      env.TOKEN_ENCRYPTION_KEY
    );

  if (
    keyBytes.length !== 32
  ) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must be exactly 32 bytes"
    );
  }

  return crypto.subtle.importKey(
    "raw",
    keyBytes,
    {
      name: "AES-GCM"
    },
    false,
    [
      "encrypt",
      "decrypt"
    ]
  );
}


async function encryptToken(
  token,
  env
) {
  const key =
    await getEncryptionKey(
      env
    );

  const iv =
    crypto.getRandomValues(
      new Uint8Array(12)
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      new TextEncoder().encode(
        token
      )
    );

  return JSON.stringify({
    iv:
      bytesToBase64Url(iv),

    data:
      bytesToBase64Url(
        new Uint8Array(
          encrypted
        )
      )
  });
}


/* =========================================================
   LOCALHOST VALIDATION
========================================================= */

function isAllowedLocalReturnUrl(
  value
) {
  try {

    const url =
      new URL(value);

    /*
      Only HTTP/HTTPS localhost
      addresses are accepted.
    */

    if (
      url.protocol !== "http:" &&
      url.protocol !== "https:"
    ) {
      return false;
    }

    const hostname =
      url.hostname.toLowerCase();

    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1"
    ) {
      return true;
    }

    return false;

  } catch {
    return false;
  }
}


/* =========================================================
   OAUTH STATE
========================================================= */

async function createOAuthState(
  vertexId,
  returnUrl,
  env
) {
  const now =
    Math.floor(
      Date.now() / 1000
    );

  const payload = {
    vertexId,
    returnUrl,
    iat: now,
    exp: now + 10 * 60,

    /*
      Random one-time identifier.
    */
    nonce:
      bytesToBase64Url(
        crypto.getRandomValues(
          new Uint8Array(16)
        )
      )
  };

  const encoded =
    bytesToBase64Url(
      new TextEncoder().encode(
        JSON.stringify(payload)
      )
    );

  const signature =
    bytesToBase64Url(
      await hmac(
        env.JWT_SECRET,
        encoded
      )
    );

  return `${encoded}.${signature}`;
}


async function verifyOAuthState(
  state,
  env
) {
  const parts =
    String(state || "")
      .split(".");

  if (
    parts.length !== 2
  ) {
    return null;
  }

  const [
    payload,
    signature
  ] = parts;

  const expected =
    bytesToBase64Url(
      await hmac(
        env.JWT_SECRET,
        payload
      )
    );

  if (
    signature !== expected
  ) {
    return null;
  }

  try {

    const data =
      JSON.parse(
        new TextDecoder().decode(
          base64UrlToBytes(
            payload
          )
        )
      );

    const now =
      Math.floor(
        Date.now() / 1000
      );

    if (
      !data.vertexId ||
      !data.returnUrl ||
      !data.exp ||
      data.exp <= now
    ) {
      return null;
    }

    if (
      !isAllowedLocalReturnUrl(
        data.returnUrl
      )
    ) {
      return null;
    }

    return data;

  } catch {
    return null;
  }
}


/* =========================================================
   GOOGLE START
========================================================= */

async function googleStart(
  request,
  env
) {
  const claims =
    await getAuthenticatedUser(
      request,
      env
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

  const url =
    new URL(
      request.url
    );

  const returnUrl =
    url.searchParams.get(
      "return_url"
    );

  if (
    !returnUrl
  ) {
    return json(
      {
        error:
          "return_url is required"
      },
      400
    );
  }

  if (
    !isAllowedLocalReturnUrl(
      returnUrl
    )
  ) {
    return json(
      {
        error:
          "return_url must be a localhost or 127.0.0.1 URL"
      },
      400
    );
  }

  if (
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET
  ) {
    return json(
      {
        error:
          "Google OAuth configuration is incomplete"
      },
      500
    );
  }

  const state =
    await createOAuthState(
      claims.sub,
      returnUrl,
      env
    );

  const googleUrl =
    new URL(
      GOOGLE_AUTH_URL
    );

  googleUrl.searchParams.set(
    "client_id",
    env.GOOGLE_CLIENT_ID
  );

  googleUrl.searchParams.set(
    "redirect_uri",
    GOOGLE_REDIRECT_URI
  );

  googleUrl.searchParams.set(
    "response_type",
    "code"
  );

  googleUrl.searchParams.set(
    "scope",
    GOOGLE_SCOPES
  );

  googleUrl.searchParams.set(
    "access_type",
    "offline"
  );

  googleUrl.searchParams.set(
    "include_granted_scopes",
    "true"
  );

  googleUrl.searchParams.set(
    "prompt",
    "consent"
  );

  googleUrl.searchParams.set(
    "state",
    state
  );

  return Response.redirect(
    googleUrl.toString(),
    302
  );
}


/* =========================================================
   GOOGLE TOKEN EXCHANGE
========================================================= */

async function exchangeGoogleCode(
  code,
  env
) {
  const body =
    new URLSearchParams();

  body.set(
    "code",
    code
  );

  body.set(
    "client_id",
    env.GOOGLE_CLIENT_ID
  );

  body.set(
    "client_secret",
    env.GOOGLE_CLIENT_SECRET
  );

  body.set(
    "redirect_uri",
    GOOGLE_REDIRECT_URI
  );

  body.set(
    "grant_type",
    "authorization_code"
  );

  const response =
    await fetch(
      GOOGLE_TOKEN_URL,
      {
        method: "POST",

        headers: {
          "content-type":
            "application/x-www-form-urlencoded"
        },

        body
      }
    );

  const data =
    await response.json();

  if (
    !response.ok
  ) {
    console.error(
      "Google token exchange:",
      data
    );

    throw new Error(
      "Google token exchange failed"
    );
  }

  return data;
}


/* =========================================================
   GOOGLE ACCOUNT
========================================================= */

async function getGoogleAccount(
  accessToken
) {
  const response =
    await fetch(
      GOOGLE_USERINFO_URL,
      {
        headers: {
          authorization:
            `Bearer ${accessToken}`
        }
      }
    );

  if (!response.ok) {
    return null;
  }

  return response.json();
}


/* =========================================================
   GOOGLE CALLBACK
========================================================= */

async function googleCallback(
  request,
  env
) {
  const url =
    new URL(
      request.url
    );

  const error =
    url.searchParams.get(
      "error"
    );

  const code =
    url.searchParams.get(
      "code"
    );

  const state =
    url.searchParams.get(
      "state"
    );


  if (error) {

    /*
      We cannot trust an arbitrary return URL
      until the state has been verified.
    */

    if (state) {

      const stateData =
        await verifyOAuthState(
          state,
          env
        );

      if (
        stateData?.returnUrl
      ) {

        const returnUrl =
          new URL(
            stateData.returnUrl
          );

        returnUrl.searchParams.set(
          "google",
          "cancelled"
        );

        return Response.redirect(
          returnUrl.toString(),
          302
        );
      }
    }

    return json(
      {
        error:
          "Google authorization cancelled"
      },
      400
    );
  }


  if (
    !code ||
    !state
  ) {
    return json(
      {
        error:
          "Missing Google OAuth parameters"
      },
      400
    );
  }


  const stateData =
    await verifyOAuthState(
      state,
      env
    );

  if (!stateData) {
    return json(
      {
        error:
          "Invalid or expired OAuth state"
      },
      401
    );
  }


  const vertexId =
    normalizeVertexId(
      stateData.vertexId
    );

  const returnUrl =
    new URL(
      stateData.returnUrl
    );


  try {

    /*
      1. Exchange Google authorization code.
    */

    const tokenData =
      await exchangeGoogleCode(
        code,
        env
      );


    /*
      2. Get Google account.
    */

    let googleAccount =
      null;

    if (
      tokenData.access_token
    ) {
      googleAccount =
        await getGoogleAccount(
          tokenData.access_token
        );
    }


    const providerAccountId =
      googleAccount?.sub ||
      googleAccount?.email ||
      null;


    /*
      3. Find Vertex user.
    */

    const userResult =
      await tursoQuery(
        env,
        `
        SELECT id
        FROM users
        WHERE vertex_id = ?
        LIMIT 1
        `,
        [vertexId]
      );

    const userRows =
      userResult.rows || [];

    if (
      !userRows.length
    ) {
      throw new Error(
        "Vertex user not found"
      );
    }


    const userValues =
      userRows[0].values ||
      userRows[0];

    const userId =
      extractValue(
        userValues[0]
      );


    /*
      4. Check existing token.
    */

    const existingResult =
      await tursoQuery(
        env,
        `
        SELECT
          encrypted_refresh_token
        FROM cloud_connections
        WHERE user_id = ?
          AND provider = ?
        LIMIT 1
        `,
        [
          userId,
          GOOGLE_PROVIDER
        ]
      );

    const existingRows =
      existingResult.rows ||
      [];

    let encryptedRefreshToken =
      null;

    if (
      existingRows.length
    ) {

      const values =
        existingRows[0].values ||
        existingRows[0];

      encryptedRefreshToken =
        extractValue(
          values[0]
        );
    }


    /*
      5. Google normally gives a refresh token
         on the first offline authorization.

         If Google doesn't return one later,
         preserve the existing encrypted token.
    */

    if (
      tokenData.refresh_token
    ) {

      encryptedRefreshToken =
        await encryptToken(
          tokenData.refresh_token,
          env
        );
    }


    if (
      !encryptedRefreshToken
    ) {

      throw new Error(
        "Google did not provide a refresh token"
      );
    }


    /*
      6. Save encrypted token.
    */

    const now =
      new Date().toISOString();

    await tursoQuery(
      env,
      `
      INSERT INTO cloud_connections
      (
        user_id,
        provider,
        provider_account_id,
        encrypted_refresh_token,
        scopes,
        status,
        created_at,
        updated_at
      )
      VALUES
      (?, ?, ?, ?, ?, 'active', ?, ?)

      ON CONFLICT(user_id, provider)
      DO UPDATE SET

        provider_account_id =
          excluded.provider_account_id,

        encrypted_refresh_token =
          excluded.encrypted_refresh_token,

        scopes =
          excluded.scopes,

        status =
          'active',

        updated_at =
          excluded.updated_at
      `,
      [
        userId,
        GOOGLE_PROVIDER,
        providerAccountId,
        encryptedRefreshToken,
        tokenData.scope ||
          GOOGLE_SCOPES,
        now,
        now
      ]
    );


    console.log({
      googleConnected:
        true,

      vertexId,

      providerAccount:
        googleAccount?.email ||
        providerAccountId ||
        "connected"
    });


    /*
      7. Return to LOCAL setup application.
    */

    returnUrl.searchParams.set(
      "google",
      "connected"
    );

    returnUrl.searchParams.set(
      "vertexId",
      vertexId
    );

    return Response.redirect(
      returnUrl.toString(),
      302
    );

  } catch (error) {

    console.error(
      "Google callback error:",
      error
    );

    returnUrl.searchParams.set(
      "google",
      "error"
    );

    returnUrl.searchParams.set(
      "message",
      "Google Drive connection failed"
    );

    return Response.redirect(
      returnUrl.toString(),
      302
    );
  }
}


/* =========================================================
   GOOGLE STATUS
========================================================= */

async function googleStatus(
  request,
  env
) {
  const claims =
    await getAuthenticatedUser(
      request,
      env
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

  const result =
    await tursoQuery(
      env,
      `
      SELECT
        provider,
        provider_account_id,
        scopes,
        status,
        created_at,
        updated_at
      FROM cloud_connections

      WHERE user_id = (
        SELECT id
        FROM users
        WHERE vertex_id = ?
        LIMIT 1
      )

      AND provider = ?

      LIMIT 1
      `,
      [
        claims.sub,
        GOOGLE_PROVIDER
      ]
    );

  const rows =
    result.rows || [];

  if (!rows.length) {
    return json({
      success: true,
      connected: false,
      provider:
        GOOGLE_PROVIDER
    });
  }

  const values =
    rows[0].values ||
    rows[0];

  return json({
    success: true,

    connected: true,

    provider:
      extractValue(
        values[0]
      ),

    providerAccountId:
      extractValue(
        values[1]
      ),

    scopes:
      extractValue(
        values[2]
      ),

    status:
      extractValue(
        values[3]
      ),

    createdAt:
      extractValue(
        values[4]
      ),

    updatedAt:
      extractValue(
        values[5]
      )
  });
}


/* =========================================================
   DISCONNECT
========================================================= */

async function googleDisconnect(
  request,
  env
) {
  const claims =
    await getAuthenticatedUser(
      request,
      env
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

  await tursoQuery(
    env,
    `
    DELETE FROM cloud_connections

    WHERE user_id = (
      SELECT id
      FROM users
      WHERE vertex_id = ?
      LIMIT 1
    )

    AND provider = ?
    `,
    [
      claims.sub,
      GOOGLE_PROVIDER
    ]
  );

  return json({
    success: true,
    connected: false
  });
}


/* =========================================================
   HEALTH
========================================================= */

function health() {
  return json({
    status: "ok",
    service:
      "vertexid-api",
    version:
      "0.3.0"
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
        Required API secrets.
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


      /*
        HEALTH
      */

      if (
        url.pathname ===
          "/api/health" &&
        request.method ===
          "GET"
      ) {
        return health();
      }


      /*
        REGISTER
      */

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


      /*
        LOGIN
      */

      if (
        url.pathname ===
          "/api/auth/login" &&
        request.method ===
          "POST"
      ) {

        await ensureSchema(
          env
        );

        return login(
          request,
          env
        );
      }


      /*
        ME
      */

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


      /*
        GOOGLE START

        Example:

        GET /api/cloud/google/start
            ?return_url=http://127.0.0.1:43721/oauth/callback

        Authorization:
        Bearer YOUR_JWT
      */

      if (
        url.pathname ===
          "/api/cloud/google/start" &&
        request.method ===
          "GET"
      ) {

        return googleStart(
          request,
          env
        );
      }


      /*
        GOOGLE CALLBACK

        Google calls this.
      */

      if (
        url.pathname ===
          "/api/cloud/google/callback" &&
        request.method ===
          "GET"
      ) {

        await ensureSchema(
          env
        );

        return googleCallback(
          request,
          env
        );
      }


      /*
        GOOGLE STATUS
      */

      if (
        url.pathname ===
          "/api/cloud/google/status" &&
        request.method ===
          "GET"
      ) {

        return googleStatus(
          request,
          env
        );
      }


      /*
        GOOGLE DISCONNECT
      */

      if (
        url.pathname ===
          "/api/cloud/google/disconnect" &&
        request.method ===
          "POST"
      ) {

        return googleDisconnect(
          request,
          env
        );
      }


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