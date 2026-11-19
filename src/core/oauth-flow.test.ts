import { webcrypto } from "node:crypto";
import { beforeAll, afterEach, describe, expect, it, vi } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import type {
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  TokenResponse,
} from "@/types";
import { Auth } from "./client";
import { WebAuth } from "../adapters/web";
import { MemoryStorageAdapter } from "./storage";

const origin = "https://aegis.example.com";
const issuer = `${origin}/api`;
const metadata = {
  issuer,
  authorization_endpoint: `${issuer}/authorize`,
  token_endpoint: `${issuer}/token`,
  jwks_uri: `${issuer}/jwks`,
  response_types_supported: ["code"],
  code_challenge_methods_supported: ["S256"],
  id_token_signing_alg_values_supported: ["RS256"],
};
const flowKey = "###aegis@portal@flow###";
let signingKey: CryptoKey;
let publicJWK: JWK;

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  signingKey = pair.privateKey;
  publicJWK = {
    ...(await exportJWK(pair.publicKey)),
    kid: "test-rsa",
    alg: "RS256",
    use: "sig",
  };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function sign(
  nonce: string | undefined,
  overrides: Record<string, unknown> = {},
  algorithm = "RS256",
) {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({
    iss: issuer,
    aud: "portal",
    sub: "user-1",
    iat: now,
    exp: now + 3600,
    nonce,
    nickname: "Ada",
    picture: "https://example.com/ada.png",
    ...overrides,
  }).setProtectedHeader({ alg: algorithm, kid: "test-rsa" });
  return jwt.sign(
    algorithm === "HS256" ? new Uint8Array(32).fill(7) : signingKey,
  );
}

function fixture(discoveryOverrides: Record<string, unknown> = {}) {
  const requests: HttpRequestConfig[] = [];
  const storage = new MemoryStorageAdapter();
  let response: unknown;
  let jwks = { keys: [publicJWK] };
  const discovery = { ...metadata, ...discoveryOverrides };
  const http: HttpClient = {
    async request<T>(request: HttpRequestConfig): Promise<HttpResponse<T>> {
      requests.push(request);
      if (request.url === `${issuer}/.well-known/openid-configuration`)
        return { status: 200, data: discovery as T };
      if (request.url === discovery.jwks_uri)
        return { status: 200, data: jwks as T };
      if (request.url === discovery.token_endpoint)
        return { status: 200, data: response as T };
      throw new Error(`Unexpected HTTP request: ${request.url}`);
    },
  };
  const config = {
    endpoint: origin,
    clientId: "portal",
    redirectUri: "https://portal.example.com/auth/callback",
    storage,
    httpClient: http,
    crypto: webcrypto as unknown as Crypto,
  };
  const auth = new Auth(config);
  return {
    auth,
    config,
    storage,
    requests,
    setResponse(value: unknown) {
      response = value;
    },
    setKeys(keys: JWK[]) {
      jwks = { keys };
    },
  };
}

function token(
  idToken: string,
  accessToken = "opaque-paseto-access-token",
): TokenResponse {
  return {
    access_token: accessToken,
    id_token: idToken,
    refresh_token: "opaque-refresh-token",
    token_type: "Bearer",
    expires_in: 3600,
  };
}

describe("OIDC authorize contract", () => {
  it("omits credentials for every OIDC fetch and retains cookies for internal APIs", async () => {
    const f = fixture();
    const requests: { url: string; credentials?: RequestCredentials }[] = [];
    let response: TokenResponse | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, options?: RequestInit) => {
        requests.push({ url, credentials: options?.credentials });
        let data: unknown;
        if (url === `${issuer}/.well-known/openid-configuration`)
          data = metadata;
        else if (url === metadata.jwks_uri) data = { keys: [publicJWK] };
        else if (url === metadata.token_endpoint) data = response;
        else if (url === `${issuer}/connections`) data = { idp: [] };
        else throw new Error(`Unexpected fetch: ${url}`);
        return new Response(JSON.stringify(data), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
    const auth = new Auth({ ...f.config, httpClient: undefined });
    const flow = await auth.authorize({ scopes: ["openid"] });
    response = token(await sign(new URL(flow.url).searchParams.get("nonce")!));
    await auth.handleCallback("code", flow.state);
    response = token(await sign(undefined), "refreshed-access");
    await auth.refreshToken();
    await auth.getConnections();
    expect(requests).toEqual([
      {
        url: `${issuer}/.well-known/openid-configuration`,
        credentials: "omit",
      },
      { url: metadata.token_endpoint, credentials: "omit" },
      { url: metadata.jwks_uri, credentials: "omit" },
      { url: metadata.token_endpoint, credentials: "omit" },
      { url: `${issuer}/connections`, credentials: "include" },
    ]);
  });

  it("discovers endpoints and forwards independent state, nonce, PKCE and prompt", async () => {
    const f = fixture({
      authorization_endpoint: `${origin}/oauth2/authorize`,
      token_endpoint: `${origin}/oauth2/token`,
      jwks_uri: `${origin}/oauth2/jwks`,
    });
    const { url, state, pkce } = await f.auth.authorize({
      audience: "hermes",
      scopes: ["openid", "profile"],
      prompt: "login",
    });
    const authorizeURL = new URL(url);
    expect(authorizeURL.pathname).toBe("/oauth2/authorize");
    expect(authorizeURL.searchParams.get("client_id")).toBe("portal");
    expect(authorizeURL.searchParams.get("audience")).toBe("hermes");
    expect(authorizeURL.searchParams.get("scope")).toBe("openid profile");
    expect(authorizeURL.searchParams.get("prompt")).toBe("login");
    expect(authorizeURL.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeURL.searchParams.get("code_challenge")).toBe(
      pkce.codeChallenge,
    );
    const nonce = authorizeURL.searchParams.get("nonce")!;
    expect(nonce).toHaveLength(43);
    expect(state).toHaveLength(43);
    expect(nonce).not.toBe(state);
    expect(nonce).not.toBe(pkce.codeVerifier);
    expect(JSON.parse((await f.storage.getItem(flowKey))!)).toMatchObject({
      state,
      nonce,
    });
    f.setResponse(token(await sign(nonce)));
    await f.auth.handleCallback("code", state);
    expect(f.requests.map((request) => request.url)).toContain(
      `${origin}/oauth2/token`,
    );
    expect(f.requests.map((request) => request.url)).toContain(
      `${origin}/oauth2/jwks`,
    );
  });

  it.each([
    { issuer: `${origin}/other` },
    { authorization_endpoint: "https://attacker.example.com/authorize" },
    { token_endpoint: "http://aegis.example.com/token" },
    { jwks_uri: `${issuer}/jwks#fragment` },
    { jwks_uri: "https://user:password@aegis.example.com/jwks" },
    { response_types_supported: ["token"] },
    { id_token_signing_alg_values_supported: ["HS256"] },
    { code_challenge_methods_supported: ["plain"] },
  ])("rejects unsafe or inconsistent metadata %j", async (overrides) => {
    const f = fixture(overrides);
    await expect(f.auth.authorize({ scopes: ["openid"] })).rejects.toThrow();
    expect(await f.storage.getItem(flowKey)).toBeNull();
    expect(f.requests).toHaveLength(1);
  });

  it("requires secure crypto without falling back to Math.random", async () => {
    const f = fixture();
    const auth = new Auth({ ...f.config, crypto: {} as Crypto });
    await expect(auth.authorize({ scopes: ["openid"] })).rejects.toThrow(
      "Secure Web Crypto",
    );
  });

  it.each([-1, NaN, Infinity, 1.5])(
    "rejects invalid maxAge %s before network requests",
    async (maxAge) => {
      const f = fixture();
      await expect(
        f.auth.authorize({ scopes: ["openid"], maxAge }),
      ).rejects.toThrow("maxAge");
      expect(f.requests).toHaveLength(0);
    },
  );

  it.each([0, 300])(
    "passes maxAge %s and validates fresh auth_time",
    async (maxAge) => {
      const f = fixture();
      const flow = await f.auth.authorize({ scopes: ["openid"], maxAge });
      expect(new URL(flow.url).searchParams.get("max_age")).toBe(
        String(maxAge),
      );
      const saved = JSON.parse((await f.storage.getItem(flowKey))!);
      f.setResponse(
        token(
          await sign(saved.nonce, { auth_time: Math.floor(Date.now() / 1000) }),
        ),
      );
      await f.auth.handleCallback("code", flow.state);
      expect(await f.auth.getUser()).toMatchObject({
        auth_time: expect.any(Number),
      });
    },
  );

  it.each([
    { maxAge: 0, authTime: undefined },
    { maxAge: 0, authTime: 1 },
    { maxAge: 300, authTime: 1 },
  ])(
    "rejects missing or stale requested authentication %j",
    async ({ maxAge, authTime }) => {
      const f = fixture();
      const flow = await f.auth.authorize({ scopes: ["openid"], maxAge });
      f.setResponse(
        token(
          await sign(new URL(flow.url).searchParams.get("nonce")!, {
            auth_time: authTime,
          }),
        ),
      );
      await expect(
        f.auth.handleCallback("code", flow.state),
      ).rejects.toMatchObject({ code: "invalid_token" });
      expect(await f.auth.getAccessToken()).toBeNull();
    },
  );
});

describe("OIDC callback validation", () => {
  it("accepts an RSA-signed ID token before emitting login and keeps the access token opaque", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({
      audience: "hermes",
      scopes: ["openid", "profile"],
    });
    const nonce = new URL(flow.url).searchParams.get("nonce")!;
    f.setResponse(
      token(
        await sign(nonce, {
          email: "ada@example.com",
          phone_number: "+123456789",
        }),
      ),
    );
    await f.auth.saveReturnTo("/projects");
    const login = vi.fn();
    f.auth.on("login", login);
    // A new instance handles the callback using persisted state, nonce and requested audience.
    const restored = new Auth(f.config);
    restored.on("login", login);
    expect((await restored.handleCallback("code", flow.state)).returnTo).toBe(
      "/projects",
    );
    expect(await restored.getAccessToken("hermes")).toBe(
      "opaque-paseto-access-token",
    );
    expect(await restored.getAccessToken()).toBe("opaque-paseto-access-token");
    expect(await restored.getUser()).toMatchObject({
      sub: "user-1",
      nickname: "Ada",
      email: "ada@example.com",
      phone_number: "+123456789",
      iat: expect.any(Number),
      exp: expect.any(Number),
    });
    expect(login).toHaveBeenCalledTimes(1);
    expect(await f.storage.getItem(flowKey)).toBeNull();
  });

  it.each([undefined, "", "wrong-state"])(
    "rejects missing/mismatching callback state %j before exchanging code",
    async (state) => {
      const f = fixture();
      await f.auth.authorize({ scopes: ["openid"] });
      await expect(f.auth.handleCallback("code", state)).rejects.toThrow(
        "State mismatch",
      );
      expect(
        f.requests.filter((request) => request.method === "POST"),
      ).toHaveLength(0);
      expect(await f.storage.getItem(flowKey)).toBeNull();
    },
  );

  it("rejects callback state when no flow was saved", async () => {
    const f = fixture();
    await expect(
      f.auth.handleCallback("code", "unsolicited-state"),
    ).rejects.toThrow("State mismatch");
    expect(f.requests).toHaveLength(0);
  });

  it.each([
    { iss: "https://attacker.example.com/api" },
    { aud: "another-client" },
    { nonce: "wrong-nonce" },
    { nonce: undefined },
    { exp: 1 },
    { iat: Math.floor(Date.now() / 1000) + 3600 },
    { iat: "2026-01-01T00:00:00Z" },
    { exp: "2026-01-01T00:00:00Z" },
    { sub: "" },
    { aud: ["portal", "other"] },
    { aud: "portal", azp: "another-client" },
  ])(
    "rejects invalid signed claims %j before persisting any credentials",
    async (overrides) => {
      const f = fixture();
      const flow = await f.auth.authorize({
        audience: "hermes",
        scopes: ["openid"],
      });
      const nonce = new URL(flow.url).searchParams.get("nonce")!;
      f.setResponse(token(await sign(nonce, overrides)));
      const login = vi.fn();
      f.auth.on("login", login);
      await expect(
        f.auth.handleCallback("code", flow.state),
      ).rejects.toMatchObject({ code: "invalid_token" });
      expect(await f.auth.getAccessToken("hermes")).toBeNull();
      expect(
        await f.storage.getItem("###aegis@portal@rt@hermes###"),
      ).toBeNull();
      expect(await f.auth.getUser()).toBeNull();
      expect(login).not.toHaveBeenCalled();
      expect(await f.storage.getItem(flowKey)).toBeNull();
    },
  );

  it("accepts an audience array with the matching authorized party", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({ scopes: ["openid"] });
    f.setResponse(
      token(
        await sign(new URL(flow.url).searchParams.get("nonce")!, {
          aud: ["portal", "other"],
          azp: "portal",
        }),
      ),
    );
    await f.auth.handleCallback("code", flow.state);
    expect(await f.auth.getAccessToken()).toBe("opaque-paseto-access-token");
  });

  it.each(["tampered", "HS256", "missing"])(
    "rejects %s ID tokens",
    async (mode) => {
      const f = fixture();
      const flow = await f.auth.authorize({ scopes: ["openid"] });
      const nonce = new URL(flow.url).searchParams.get("nonce")!;
      let jwt = await sign(nonce, {}, mode === "HS256" ? "HS256" : "RS256");
      if (mode === "tampered") {
        const parts = jwt.split(".");
        parts[1] = Buffer.from(
          JSON.stringify({
            iss: issuer,
            aud: "portal",
            sub: "attacker",
            nonce,
            iat: 1,
            exp: 9999999999,
          }),
        ).toString("base64url");
        jwt = parts.join(".");
      }
      const response = token(jwt);
      if (mode === "missing") delete response.id_token;
      f.setResponse(response);
      await expect(
        f.auth.handleCallback("code", flow.state),
      ).rejects.toMatchObject({ code: "invalid_token" });
      expect(await f.auth.getAccessToken()).toBeNull();
    },
  );

  it("does not let a failed new login destroy an existing valid session", async () => {
    const f = fixture();
    const first = await f.auth.authorize({
      audience: "hermes",
      scopes: ["openid"],
    });
    f.setResponse(
      token(
        await sign(new URL(first.url).searchParams.get("nonce")!),
        "existing-access",
      ),
    );
    await f.auth.handleCallback("code", first.state);
    const second = await f.auth.authorize({
      audience: "hermes",
      scopes: ["openid"],
    });
    f.setResponse(token(await sign("wrong-nonce"), "invalid-new-access"));
    await expect(f.auth.handleCallback("code", second.state)).rejects.toThrow();
    expect(await f.auth.getAccessToken("hermes")).toBe("existing-access");
  });

  it("clears an OAuth error callback flow while preserving an existing valid session", async () => {
    const f = fixture();
    const first = await f.auth.authorize({ scopes: ["openid"] });
    f.setResponse(
      token(await sign(new URL(first.url).searchParams.get("nonce")!)),
    );
    await f.auth.handleCallback("code", first.state);
    const second = await f.auth.authorize({ scopes: ["openid"] });
    await f.auth.saveReturnTo("/protected");
    const replaceState = vi.fn();
    vi.stubGlobal("window", {
      location: {
        search: `?error=access_denied&error_description=Cancelled&state=${second.state}`,
        pathname: "/auth/callback",
      },
      history: { replaceState },
    });
    const web = new WebAuth(f.config);
    expect(await web.handleRedirectCallback()).toEqual({
      success: false,
      error: "Cancelled",
    });
    expect(await f.storage.getItem(flowKey)).toBeNull();
    expect(await f.storage.getItem("###aegis@portal@return-to###")).toBeNull();
    expect(await web.getAccessToken()).toBe("opaque-paseto-access-token");
    expect(replaceState).toHaveBeenCalled();
  });

  it.each(["", "wrong-state"])(
    "rejects OAuth error callbacks with invalid state %j and clears the pending flow",
    async (state) => {
      const f = fixture();
      await f.auth.authorize({ scopes: ["openid"] });
      vi.stubGlobal("window", {
        location: {
          search: `?error=access_denied&state=${state}`,
          pathname: "/auth/callback",
        },
        history: { replaceState: vi.fn() },
      });
      expect(await new WebAuth(f.config).handleRedirectCallback()).toEqual({
        success: false,
        error: "State mismatch",
      });
      expect(await f.storage.getItem(flowKey)).toBeNull();
    },
  );

  it("requires a new login for old PASETO identity sessions without trusted auth metadata", async () => {
    const f = fixture();
    await f.storage.setItem("###aegis@portal@at@hermes###", "old-access");
    await f.storage.setItem("###aegis@portal@rt@hermes###", "old-refresh");
    await f.storage.setItem(
      "###aegis@portal@id-token###",
      JSON.stringify({ sub: "old-user", exp: "2099-01-01T00:00:00Z" }),
    );
    expect(await f.auth.isAuthenticated("hermes")).toBe(false);
    expect(await f.auth.getAccessToken("hermes")).toBeNull();
    expect(await f.auth.getUser()).toBeNull();
  });
});

describe("opaque multi-audience token lifecycle", () => {
  it("persists each requested audience and removes all on logout", async () => {
    const f = fixture();
    const audiences = {
      hermes: { scope: "openid read" },
      iris: { scope: "openid profile" },
    };
    const flow = await f.auth.authorize({ audiences, scopes: ["openid"] });
    expect(
      JSON.parse(new URL(flow.url).searchParams.get("audiences")!),
    ).toEqual(audiences);
    const jwt = await sign(new URL(flow.url).searchParams.get("nonce")!);
    f.setResponse({
      iris: token(jwt, "iris-access"),
      hermes: token(jwt, "hermes-access"),
    });
    await f.auth.handleCallback("code", flow.state);
    expect(await f.auth.getAccessToken("iris")).toBe("iris-access");
    expect(await f.auth.getAccessToken("hermes")).toBe("hermes-access");
    expect(await f.auth.getAccessToken()).toBe("hermes-access");
    await f.auth.logout();
    expect(await f.auth.getAccessToken("iris")).toBeNull();
    expect(await f.auth.getAccessToken("hermes")).toBeNull();
    expect(await f.auth.getUser()).toBeNull();
  });

  it("validates every audience ID token before writing any token", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({
      audiences: { hermes: {}, iris: {} },
      scopes: ["openid"],
    });
    const jwt = await sign(new URL(flow.url).searchParams.get("nonce")!);
    f.setResponse({ hermes: token(jwt), iris: token(await sign("wrong")) });
    await expect(f.auth.handleCallback("code", flow.state)).rejects.toThrow();
    expect(await f.auth.getAccessToken("hermes")).toBeNull();
    expect(await f.storage.getItem("###aegis@portal@rt@hermes###")).toBeNull();
  });

  it("rejects unexpected response audiences", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({
      audiences: { hermes: {} },
      scopes: ["openid"],
    });
    f.setResponse({
      attacker: token(await sign(new URL(flow.url).searchParams.get("nonce")!)),
    });
    await expect(f.auth.handleCallback("code", flow.state)).rejects.toThrow(
      "audiences do not match",
    );
  });

  it("uses expires_in for opaque AT expiry and refreshes without requiring a new ID token", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({
      audience: "hermes",
      scopes: ["openid", "offline_access"],
    });
    f.setResponse({
      ...token(await sign(new URL(flow.url).searchParams.get("nonce")!)),
      expires_in: 1,
    });
    await f.auth.handleCallback("code", flow.state);
    f.setResponse({
      access_token: "refreshed-access",
      expires_in: 3600,
      token_type: "Bearer",
    });
    expect(await f.auth.getAccessToken("hermes")).toBe("refreshed-access");
    const request = f.requests.filter((item) => item.method === "POST").at(-1)!;
    expect(new URLSearchParams(request.body as string).get("grant_type")).toBe(
      "refresh_token",
    );
    expect(
      new URLSearchParams(request.body as string).get("refresh_token"),
    ).toBe("opaque-refresh-token");
    expect(await f.storage.getItem("###aegis@portal@rt@hermes###")).toBe(
      "opaque-refresh-token",
    );
  });

  it.each([
    { sub: "another-user" },
    { iss: "https://wrong.example.com/api" },
    { aud: "wrong-client" },
    { exp: 1 },
    { nonce: "wrong" },
  ])(
    "rejects invalid refreshed identity %j before updating credentials",
    async (overrides) => {
      const f = fixture();
      const flow = await f.auth.authorize({
        audience: "hermes",
        scopes: ["openid"],
      });
      f.setResponse(
        token(
          await sign(new URL(flow.url).searchParams.get("nonce")!),
          "original-access",
        ),
      );
      await f.auth.handleCallback("code", flow.state);
      f.setResponse(
        token(await sign(undefined, overrides), "invalid-refreshed-access"),
      );
      const refreshed = vi.fn();
      f.auth.on("token_refreshed", refreshed);
      await expect(
        f.auth.refreshToken(undefined, "hermes"),
      ).rejects.toMatchObject({ code: "invalid_token" });
      expect(await f.auth.getAccessToken("hermes")).toBe("original-access");
      expect(refreshed).not.toHaveBeenCalled();
    },
  );

  it("accepts a valid refreshed ID token without nonce and preserves its subject", async () => {
    const f = fixture();
    const flow = await f.auth.authorize({ scopes: ["openid"] });
    f.setResponse(
      token(await sign(new URL(flow.url).searchParams.get("nonce")!)),
    );
    await f.auth.handleCallback("code", flow.state);
    f.setResponse(
      token(await sign(undefined, { nickname: "Updated" }), "new-access"),
    );
    await f.auth.refreshToken();
    expect(await f.auth.getUser()).toMatchObject({
      sub: "user-1",
      nickname: "Updated",
    });
    expect(await f.auth.getAccessToken()).toBe("new-access");
  });

  it("refreshes JWKS when a new signing key appears", async () => {
    const f = fixture();
    const first = await f.auth.authorize({ scopes: ["openid"] });
    f.setResponse(
      token(await sign(new URL(first.url).searchParams.get("nonce")!)),
    );
    await f.auth.handleCallback("code", first.state);
    const rotated = await generateKeyPair("RS256", { extractable: true });
    f.setKeys([
      {
        ...(await exportJWK(rotated.publicKey)),
        kid: "rotated",
        alg: "RS256",
        use: "sig",
      },
    ]);
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({
      iss: issuer,
      aud: "portal",
      sub: "user-1",
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: "RS256", kid: "rotated" })
      .sign(rotated.privateKey);
    f.setResponse(token(jwt, "rotated-access"));
    await f.auth.refreshToken();
    expect(await f.auth.getAccessToken()).toBe("rotated-access");
    expect(
      f.requests.filter((request) => request.url === metadata.jwks_uri),
    ).toHaveLength(2);
  });
});
