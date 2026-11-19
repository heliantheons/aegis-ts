import {
  createLocalJWKSet,
  jwtVerify,
  errors,
  type JSONWebKeySet,
  type JWTVerifyGetKey,
} from "jose";
import type { HttpClient, IDTokenClaims, TokenResponse } from "@/types";
import { AuthError, ErrorCodes } from "@/types";

interface ProviderMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  response_types_supported: string[];
  id_token_signing_alg_values_supported: string[];
  code_challenge_methods_supported: string[];
}

export interface IDTokenExpectation {
  nonce?: string;
  subject?: string;
  maxAge?: number;
  authenticationStartedAt?: number;
}

/** Discovery and JWKS always use the caller's HTTP adapter, including in tests. */
export class OIDCProvider {
  readonly issuer: string;
  private metadataPromise?: Promise<ProviderMetadata>;
  private keys?: JWTVerifyGetKey;
  private keysAt = 0;
  private keysPromise?: Promise<JWTVerifyGetKey>;

  constructor(
    private http: HttpClient,
    endpoint: string,
    private clientId: string,
  ) {
    const url = new URL(endpoint);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.pathname !== "/" && url.pathname !== "")
    ) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        "endpoint must be the Aegis origin",
      );
    }
    this.secureURL(url.toString(), url.origin);
    this.issuer = `${url.origin}/api`;
  }

  metadata(): Promise<ProviderMetadata> {
    this.metadataPromise ??= this.fetchMetadata().catch((error) => {
      this.metadataPromise = undefined;
      throw error;
    });
    return this.metadataPromise;
  }

  invalidateKeys(): void {
    this.keys = undefined;
    this.keysAt = 0;
  }

  async verifyIDToken(
    token: string,
    expected: IDTokenExpectation,
  ): Promise<IDTokenClaims> {
    await this.metadata();
    try {
      let keys = await this.resolveKeys();
      const options = {
        issuer: this.issuer,
        audience: this.clientId,
        algorithms: ["RS256"],
        requiredClaims: ["iss", "sub", "aud", "iat", "exp"],
      };
      let result;
      try {
        result = await jwtVerify(token, keys, options);
      } catch (error) {
        if (!(error instanceof errors.JWKSNoMatchingKey)) throw error;
        this.invalidateKeys();
        keys = await this.resolveKeys();
        result = await jwtVerify(token, keys, options);
      }
      const claims = result.payload;
      const now = Date.now() / 1000;
      if (
        typeof claims.sub !== "string" ||
        !claims.sub ||
        typeof claims.iat !== "number" ||
        !Number.isFinite(claims.iat) ||
        claims.iat > now ||
        typeof claims.exp !== "number" ||
        !Number.isFinite(claims.exp) ||
        claims.exp <= claims.iat ||
        (claims.azp !== undefined && claims.azp !== this.clientId) ||
        (Array.isArray(claims.aud) &&
          claims.aud.length > 1 &&
          claims.azp !== this.clientId) ||
        (expected.nonce !== undefined && claims.nonce !== expected.nonce) ||
        (expected.subject !== undefined && claims.sub !== expected.subject)
      ) {
        throw new Error("ID token claims do not match the authentication flow");
      }
      for (const field of [
        "nonce",
        "nickname",
        "picture",
        "email",
        "phone_number",
      ] as const) {
        if (claims[field] !== undefined && typeof claims[field] !== "string")
          throw new Error(`Invalid ${field}`);
      }
      if (
        claims.auth_time !== undefined &&
        (typeof claims.auth_time !== "number" ||
          !Number.isFinite(claims.auth_time) ||
          claims.auth_time > now)
      ) {
        throw new Error("Invalid auth_time");
      }
      if (expected.maxAge !== undefined) {
        const earliest =
          expected.maxAge === 0
            ? (expected.authenticationStartedAt ?? Math.floor(now))
            : Math.floor(now) - expected.maxAge;
        if (
          typeof claims.auth_time !== "number" ||
          claims.auth_time < earliest
        ) {
          throw new Error("ID token authentication is older than max_age");
        }
      }
      return claims as unknown as IDTokenClaims;
    } catch (error) {
      throw new AuthError(
        ErrorCodes.INVALID_TOKEN,
        error instanceof Error ? error.message : "Invalid ID token",
      );
    }
  }

  private async fetchMetadata(): Promise<ProviderMetadata> {
    const res = await this.http.request<ProviderMetadata>({
      method: "GET",
      url: `${this.issuer}/.well-known/openid-configuration`,
      credentials: "omit",
    });
    const data = res.data;
    if (
      res.status !== 200 ||
      !data ||
      data.issuer !== this.issuer ||
      !Array.isArray(data.response_types_supported) ||
      !data.response_types_supported.includes("code") ||
      !Array.isArray(data.id_token_signing_alg_values_supported) ||
      !data.id_token_signing_alg_values_supported.includes("RS256") ||
      !Array.isArray(data.code_challenge_methods_supported) ||
      !data.code_challenge_methods_supported.includes("S256")
    ) {
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        "Invalid OIDC discovery metadata",
      );
    }
    const origin = new URL(this.issuer).origin;
    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "jwks_uri",
    ] as const) {
      this.secureURL(data[field], origin);
    }
    return data;
  }

  private secureURL(value: string, origin: string): void {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new AuthError(ErrorCodes.SERVER_ERROR, "Invalid OIDC endpoint URL");
    }
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (
      url.origin !== origin ||
      url.username ||
      url.password ||
      url.hash ||
      url.search ||
      (url.protocol !== "https:" && !(url.protocol === "http:" && loopback))
    ) {
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        "Insecure OIDC endpoint URL",
      );
    }
  }

  private async resolveKeys(): Promise<JWTVerifyGetKey> {
    if (this.keys && Date.now() - this.keysAt < 5 * 60_000) return this.keys;
    this.keysPromise ??= this.fetchKeys().finally(() => {
      this.keysPromise = undefined;
    });
    return this.keysPromise;
  }

  private async fetchKeys(): Promise<JWTVerifyGetKey> {
    const metadata = await this.metadata();
    const res = await this.http.request<JSONWebKeySet>({
      method: "GET",
      url: metadata.jwks_uri,
      credentials: "omit",
    });
    if (
      res.status !== 200 ||
      !res.data ||
      !Array.isArray(res.data.keys) ||
      !res.data.keys.length
    ) {
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        "Invalid OIDC JWKS response",
      );
    }
    this.keys = createLocalJWKSet(res.data);
    this.keysAt = Date.now();
    return this.keys;
  }
}

export function validateTokenResponse(
  value: unknown,
): asserts value is TokenResponse {
  if (!value || typeof value !== "object")
    throw new AuthError(ErrorCodes.INVALID_TOKEN, "Invalid token response");
  const token = value as TokenResponse;
  if (
    typeof token.access_token !== "string" ||
    !token.access_token ||
    typeof token.token_type !== "string" ||
    token.token_type.toLowerCase() !== "bearer" ||
    typeof token.expires_in !== "number" ||
    !Number.isFinite(token.expires_in) ||
    token.expires_in <= 0 ||
    (token.refresh_token !== undefined &&
      (typeof token.refresh_token !== "string" || !token.refresh_token)) ||
    (token.id_token !== undefined &&
      (typeof token.id_token !== "string" || !token.id_token))
  ) {
    throw new AuthError(ErrorCodes.INVALID_TOKEN, "Invalid token response");
  }
}
