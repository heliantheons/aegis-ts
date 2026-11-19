import type {
  StorageAdapter,
  HttpClient,
  AuthorizeOptions,
  TokenResponse,
  CallbackResult,
  MultiAudienceTokenResponse,
  PKCEParams,
} from "@/types";
import { AuthError, ErrorCodes } from "@/types";
import { generatePKCE, generateCodeVerifier } from "@utils/pkce";
import { TokenManager } from "@core/token-manager";
import { OIDCProvider } from "@core/oidc";
import { EventBus } from "@core/event-bus";

interface FlowMetadata {
  state: string;
  nonce: string;
  verifier: string;
  redirectUri: string;
  audiences: string[];
  multiAudience: boolean;
  maxAge?: number;
  authenticationStartedAt: number;
}

export interface OAuthFlowConfig {
  clientId: string;
  redirectUri: string;
  storage: StorageAdapter;
  http: HttpClient;
  oidc: OIDCProvider;
  crypto?: Crypto;
  tokens: TokenManager;
  events: EventBus;
}

export class OAuthFlow {
  private flowKey: string;
  private returnToKey: string;

  constructor(private config: OAuthFlowConfig) {
    this.flowKey = `###aegis@${config.clientId}@flow###`;
    this.returnToKey = `###aegis@${config.clientId}@return-to###`;
  }

  async authorize(
    options: AuthorizeOptions,
  ): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    if (
      options.maxAge !== undefined &&
      (!Number.isSafeInteger(options.maxAge) || options.maxAge < 0)
    ) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        "maxAge must be a non-negative integer",
      );
    }
    const metadata = await this.config.oidc.metadata();
    const pkce = await generatePKCE(64, this.config.crypto);
    const state = options.state ?? generateCodeVerifier(43, this.config.crypto);
    const nonce = generateCodeVerifier(43, this.config.crypto);
    if (!state)
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        "State must not be empty",
      );
    const audiences = options.audiences
      ? Object.keys(options.audiences)
      : [options.audience ?? ""];
    if (
      !audiences.length ||
      (options.audiences && audiences.some((audience) => !audience))
    ) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        "At least one audience is required",
      );
    }
    const flow: FlowMetadata = {
      state,
      nonce,
      verifier: pkce.codeVerifier,
      redirectUri: options.redirectUri ?? this.config.redirectUri,
      audiences,
      multiAudience: options.audiences !== undefined,
      maxAge: options.maxAge,
      authenticationStartedAt: Math.floor(Date.now() / 1000),
    };
    const scopes = [...new Set(["openid", ...options.scopes])];
    const url = new URL(metadata.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      state,
      nonce,
      scope: scopes.join(" "),
      redirect_uri: flow.redirectUri,
    }).toString();
    if (options.audiences)
      url.searchParams.set("audiences", JSON.stringify(options.audiences));
    else if (options.audience)
      url.searchParams.set("audience", options.audience);
    if (options.prompt) url.searchParams.set("prompt", options.prompt);
    if (options.maxAge !== undefined)
      url.searchParams.set("max_age", String(options.maxAge));
    await this.config.storage.setItem(this.flowKey, JSON.stringify(flow));
    return { url: url.toString(), pkce, state };
  }

  async handleCallback(code: string, state?: string): Promise<CallbackResult> {
    try {
      const raw = await this.config.storage.getItem(this.flowKey);
      let flow: FlowMetadata | null = null;
      try {
        flow = raw ? JSON.parse(raw) : null;
      } catch {
        /* Invalid saved flow is rejected below. */
      }
      if (!state || !flow?.state || state !== flow.state)
        throw new AuthError(ErrorCodes.INVALID_REQUEST, "State mismatch");
      if (
        !code ||
        !flow.verifier ||
        !flow.nonce ||
        !flow.redirectUri ||
        !Array.isArray(flow.audiences)
      ) {
        throw new AuthError(
          ErrorCodes.INVALID_REQUEST,
          "Incomplete authorization flow",
        );
      }
      // Consume the flow before the network exchange so callbacks cannot replay it.
      await this.config.storage.removeItem(this.flowKey);
      const metadata = await this.config.oidc.metadata();
      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: this.config.clientId,
        code_verifier: flow.verifier,
        redirect_uri: flow.redirectUri,
      });
      const response = await this.config.http.request<
        TokenResponse | MultiAudienceTokenResponse
      >({
        method: "POST",
        url: metadata.token_endpoint,
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString(),
        credentials: "omit",
      });
      if (response.status !== 200) {
        const error = response.data as {
          error?: string;
          error_description?: string;
        } | null;
        throw new AuthError(
          error?.error ?? ErrorCodes.INVALID_GRANT,
          error?.error_description ??
            `Token exchange failed (${response.status})`,
          undefined,
          response.status,
        );
      }
      const data = response.data;
      if (!data || typeof data !== "object")
        throw new AuthError(ErrorCodes.INVALID_TOKEN, "Invalid token response");
      let entries: [string, TokenResponse][];
      if (flow.multiAudience) {
        if (
          "access_token" in data ||
          Object.keys(data).length !== flow.audiences.length ||
          flow.audiences.some(
            (audience) => !Object.prototype.hasOwnProperty.call(data, audience),
          )
        ) {
          throw new AuthError(
            ErrorCodes.INVALID_TOKEN,
            "Token response audiences do not match the request",
          );
        }
        entries = flow.audiences.map((audience) => [
          audience,
          (data as MultiAudienceTokenResponse)[audience],
        ]);
      } else {
        if (!("access_token" in data))
          throw new AuthError(
            ErrorCodes.INVALID_TOKEN,
            "Expected a single token response",
          );
        entries = [[flow.audiences[0], data as TokenResponse]];
      }
      await this.config.tokens.establishSession(entries, {
        nonce: flow.nonce,
        maxAge: flow.maxAge,
        authenticationStartedAt: flow.authenticationStartedAt,
      });
      const tokens = entries[0][1];
      const returnTo = await this.config.storage.getItem(this.returnToKey);
      this.config.events.emit("login", tokens);
      return { ...tokens, returnTo };
    } finally {
      await this.cancel();
    }
  }

  /** Discard a callback/error flow without touching an existing authenticated session. */
  async cancel(state?: string): Promise<void> {
    try {
      if (state !== undefined) {
        const raw = await this.config.storage.getItem(this.flowKey);
        let saved: FlowMetadata | null = null;
        try {
          saved = raw ? JSON.parse(raw) : null;
        } catch {
          /* Rejected below. */
        }
        if (!state || !saved?.state || saved.state !== state)
          throw new AuthError(ErrorCodes.INVALID_REQUEST, "State mismatch");
      }
    } finally {
      await Promise.all([
        this.config.storage.removeItem(this.flowKey),
        this.config.storage.removeItem(this.returnToKey),
      ]);
    }
  }

  async saveReturnTo(path: string): Promise<void> {
    await this.config.storage.setItem(this.returnToKey, path);
  }
}
