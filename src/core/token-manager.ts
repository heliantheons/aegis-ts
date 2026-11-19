import type {
  StorageAdapter,
  HttpClient,
  TokenResponse,
  TokenStore,
  IDTokenClaims,
} from "@/types";
import { AuthError, ErrorCodes } from "@/types";
import { EventBus } from "@core/event-bus";
import {
  OIDCProvider,
  validateTokenResponse,
  type IDTokenExpectation,
} from "@core/oidc";

export interface TokenManagerConfig {
  storage: StorageAdapter;
  events: EventBus;
  http: HttpClient;
  oidc: OIDCProvider;
  clientId: string;
}

interface SessionMetadata {
  audiences: string[];
  primary: string;
  subject: string;
  nonce: string;
}

export class TokenManager {
  private s: StorageAdapter;
  private events: EventBus;
  private http: HttpClient;
  private oidc: OIDCProvider;
  private clientId: string;
  private idTokenKey: string;
  private sessionKey: string;

  constructor(config: TokenManagerConfig) {
    this.s = config.storage;
    this.events = config.events;
    this.http = config.http;
    this.oidc = config.oidc;
    this.clientId = config.clientId;
    this.idTokenKey = `###aegis@${config.clientId}@id-token###`;
    this.sessionKey = `###aegis@${config.clientId}@session###`;
  }

  private scopedKey(kind: "at" | "rt" | "expires", audience: string): string {
    return `###aegis@${this.clientId}@${kind}@${audience}###`;
  }

  /** All ID tokens are validated before replacing any existing session. */
  async establishSession(
    entries: [string, TokenResponse][],
    expected: IDTokenExpectation & { nonce: string },
  ): Promise<void> {
    const verified: IDTokenClaims[] = [];
    for (const [, response] of entries) {
      validateTokenResponse(response);
      if (!response.id_token)
        throw new AuthError(ErrorCodes.INVALID_TOKEN, "Missing ID token");
      verified.push(
        await this.oidc.verifyIDToken(response.id_token, {
          ...expected,
          subject: verified[0]?.sub,
        }),
      );
    }
    const claims = verified[0];
    if (!claims)
      throw new AuthError(ErrorCodes.INVALID_TOKEN, "Empty token response");
    await this.purgeAll();
    for (const [audience, response] of entries)
      await this.persistScoped(audience, response);
    await this.s.setItem(this.idTokenKey, JSON.stringify(claims));
    const session: SessionMetadata = {
      audiences: entries.map(([audience]) => audience),
      primary: entries[0][0],
      subject: claims.sub,
      nonce: expected.nonce,
    };
    await this.s.setItem(this.sessionKey, JSON.stringify(session));
  }

  private async persistScoped(
    audience: string,
    response: TokenResponse,
  ): Promise<void> {
    await this.s.setItem(this.scopedKey("at", audience), response.access_token);
    await this.s.setItem(
      this.scopedKey("expires", audience),
      String(Date.now() + response.expires_in * 1000),
    );
    if (response.refresh_token)
      await this.s.setItem(
        this.scopedKey("rt", audience),
        response.refresh_token,
      );
  }

  private async session(): Promise<SessionMetadata | null> {
    const raw = await this.s.getItem(this.sessionKey);
    if (!raw) return null;
    try {
      const value: SessionMetadata = JSON.parse(raw);
      if (
        !Array.isArray(value.audiences) ||
        !value.audiences.every((aud) => typeof aud === "string") ||
        typeof value.primary !== "string" ||
        !value.audiences.includes(value.primary) ||
        typeof value.subject !== "string" ||
        !value.subject ||
        typeof value.nonce !== "string" ||
        !value.nonce
      )
        return null;
      return value;
    } catch {
      return null;
    }
  }

  private async audience(requested?: string): Promise<string> {
    return requested ?? (await this.session())?.primary ?? "";
  }

  private async loadScoped(audience: string): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      this.s.getItem(this.scopedKey("at", audience)),
      this.s.getItem(this.scopedKey("rt", audience)),
    ]);
    return { accessToken, refreshToken };
  }

  private async expiredScoped(
    audience: string,
    bufferMs = 60_000,
  ): Promise<boolean> {
    const raw = await this.s.getItem(this.scopedKey("expires", audience));
    const expires = Number(raw);
    return (
      !raw || !Number.isFinite(expires) || Date.now() + bufferMs >= expires
    );
  }

  private async purgeScoped(audience: string): Promise<void> {
    await Promise.all(
      ["at", "rt", "expires"].map((kind) =>
        this.s.removeItem(
          this.scopedKey(kind as "at" | "rt" | "expires", audience),
        ),
      ),
    );
  }

  async getAccessToken(audience?: string): Promise<string | null> {
    const aud = await this.audience(audience);
    const session = await this.session();
    if (!session?.audiences.includes(aud)) return null;
    const store = await this.loadScoped(aud);
    if (!store.accessToken) return null;
    if (!(await this.expiredScoped(aud))) return store.accessToken;
    if (store.refreshToken) {
      try {
        return (await this.refreshToken(store.refreshToken, aud)).access_token;
      } catch {
        this.events.emit("token_expired");
        await this.purgeScoped(aud);
        return null;
      }
    }
    this.events.emit("token_expired");
    await this.purgeScoped(aud);
    return null;
  }

  async isAuthenticated(audience?: string): Promise<boolean> {
    const aud = await this.audience(audience);
    const session = await this.session();
    if (!session?.audiences.includes(aud)) return false;
    const store = await this.loadScoped(aud);
    if (!store.accessToken) return false;
    return !(await this.expiredScoped(aud)) || !!store.refreshToken;
  }

  async refreshToken(
    refreshToken?: string,
    audience?: string,
  ): Promise<TokenResponse> {
    const session = await this.session();
    const aud = await this.audience(audience);
    const rt = refreshToken ?? (await this.loadScoped(aud)).refreshToken;
    if (!session || !session.audiences.includes(aud) || !rt) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        "No authenticated refresh session available",
      );
    }
    const metadata = await this.oidc.metadata();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: rt,
      client_id: this.clientId,
    });
    const res = await this.http.request<TokenResponse>({
      method: "POST",
      url: metadata.token_endpoint,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (res.status !== 200)
      throw new AuthError(ErrorCodes.INVALID_GRANT, "Token refresh failed");
    validateTokenResponse(res.data);
    let claims: IDTokenClaims | undefined;
    if (res.data.id_token) {
      claims = await this.oidc.verifyIDToken(res.data.id_token, {
        subject: session.subject,
      });
      if (claims.nonce !== undefined && claims.nonce !== session.nonce) {
        throw new AuthError(
          ErrorCodes.INVALID_TOKEN,
          "Refresh ID token nonce mismatch",
        );
      }
    }
    await this.persistScoped(aud, res.data);
    if (claims) await this.s.setItem(this.idTokenKey, JSON.stringify(claims));
    this.events.emit("token_refreshed", res.data);
    return res.data;
  }

  async purgeAll(): Promise<void> {
    const session = await this.session();
    for (const audience of new Set([
      ...(session?.audiences ?? []),
      "",
      this.clientId,
    ]))
      await this.purgeScoped(audience);
    await this.s.removeItem(this.idTokenKey);
    await this.s.removeItem(this.sessionKey);
  }

  async getUser(): Promise<IDTokenClaims | null> {
    const raw = await this.s.getItem(this.idTokenKey);
    if (!raw || !(await this.session())) return null;
    try {
      const claims: IDTokenClaims = JSON.parse(raw);
      if (
        typeof claims.exp !== "number" ||
        !Number.isFinite(claims.exp) ||
        claims.exp * 1000 <= Date.now()
      )
        return null;
      return claims;
    } catch {
      return null;
    }
  }

  invalidateKeys(): void {
    this.oidc.invalidateKeys();
  }
}
