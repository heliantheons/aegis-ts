<p align="center">
  <img src="./assets/brand/hero-ice.png" width="256" alt="Aegis TypeScript logo" />
</p>

<h1 align="center">Aegis TypeScript</h1>

`@heliantheons/aegis-ts` 是框架无关的浏览器认证 SDK，支持标准 OpenID Connect Authorization Code + PKCE。`Auth` 提供纯逻辑层与可替换的存储、HTTP 适配器；`WebAuth` 提供 SPA 跳转和回调处理。运行时使用 `jose` 校验 RS256 JWT ID Token，Access Token 保留服务端的 PASETO 格式并作为不透明字符串传递。

`@heliantheons/aegis-ts` is a framework-agnostic browser SDK for OpenID Connect Authorization Code + PKCE. `Auth` provides the core with pluggable storage and HTTP; `WebAuth` handles browser redirects. ID tokens are standard RS256 JWTs verified with `jose`. Access tokens retain the server's PASETO format and the SDK treats them as opaque strings.

## 安装 / Install

```bash
pnpm add @heliantheons/aegis-ts
```

所有公共 API 都可以从包根入口导入。`/web` 子路径继续保留，用于兼容旧版本调用方。

All public APIs are available from the package root. The `/web` subpath remains available for backward compatibility.

```ts
import {
  Auth,
  WebAuth,
  AuthError,
  type AuthConfig,
  type WebAuthConfig,
} from "@heliantheons/aegis-ts";
```

## 浏览器应用 / Browser applications

```ts
import { WebAuth } from "@heliantheons/aegis-ts";

const auth = new WebAuth({
  endpoint: "https://aegis.example.com",
  clientId: "portal",
  redirectUri: `${window.location.origin}/auth/callback`,
});

await auth.authorize({
  audience: "hermes",
  scopes: ["openid", "profile", "offline_access"],
  returnTo: window.location.pathname + window.location.search,
});
```

在回调路由中完成 code exchange：

```ts
const result = await auth.handleRedirectCallback();
if (!result.success) throw new Error(result.error);
window.location.replace(result.redirectTo ?? "/");
```

获取指定 audience 的 access token。SDK 会在需要时使用 refresh token 更新令牌：

```ts
const token = await auth.getAccessToken("hermes");
const response = await fetch("/api/resource", {
  headers: { Authorization: `Bearer ${token}` },
});
```

`endpoint` 必须为 Aegis 的 origin（例如 `https://aegis.example.com`）。SDK 从 `${endpoint}/api/.well-known/openid-configuration` 发现并校验 issuer `${endpoint}/api`，使用发现的 authorization、token 和 JWKS 地址。生产地址必须使用 HTTPS；本地回环地址可使用 HTTP。SDK 使用独立的加密随机 state 和 nonce，严格校验回调 state、RS256 签名、issuer、client audience、有效期及初次登录 nonce；校验完成后才保存令牌并触发 login。

Set `endpoint` to the Aegis origin. Discovery uses `${endpoint}/api/.well-known/openid-configuration` and requires issuer `${endpoint}/api`, same-origin secure endpoints, PKCE S256, and RS256 support. HTTPS is required except for loopback development origins. Callback state must exactly match the persisted flow. Initial ID token validation, including nonce, completes before credentials are saved or `login` fires. Failed/error callbacks clear the pending flow and preserve an existing valid session. `Auth.cancelAuthorization()` also discards a pending flow.

`openid` is included automatically. Omit `audience` to use the server's configured resource; `getAccessToken()` then returns that session's primary access token. Explicit `getAccessToken("hermes")` resolves the corresponding requested audience. Token expiry comes from `expires_in`, without decoding access tokens. The multi-audience extension remains available:

```ts
await auth.authorize({
  audiences: {
    hermes: { scope: "openid read" },
    iris: { scope: "openid profile" },
  },
  scopes: ["openid", "offline_access"],
});
```

`getUser()` returns verified standard ID claims: `sub`, `iss`, `aud` (`string | string[]`), numeric `iat`/`exp` in seconds, optional numeric `auth_time`, `nonce`, `azp`, and scope-dependent `nickname`, `picture`, `email`, `phone_number`. `profile` enables nickname/picture; `email` and `phone` enable the corresponding contact claim. Refresh ID tokens must identify the same subject. Refresh responses may omit the ID token. Logout removes tokens for every audience established by the session.

Set `maxAge` to a non-negative integer number of seconds to send OIDC `max_age` (for example `maxAge: 0` requests fresh authentication). When requested, the returned ID token must include a sufficiently recent numeric `auth_time`. For `maxAge: 0`, authentication must occur at or after the saved authorization request time. `prompt` remains available independently.

Existing PASETO ID-token sessions must log in again after this upgrade. The SDK does not accept PASETO ID tokens or the former `nic`/`pic` user fields.

## 自定义集成 / Custom integration

需要替换存储或 HTTP 实现时，可以给 `WebAuth` 传入适配器，也可以直接使用底层 `Auth`：

```ts
const auth = new WebAuth({
  endpoint: "https://aegis.example.com",
  clientId: "portal",
  redirectUri: `${window.location.origin}/auth/callback`,
  storage: customStorage,
  httpClient: customHTTPClient,
});
```

Discovery and JWKS requests use the supplied `httpClient`. Secure Web Crypto is required; environments that need an explicit provider can pass `crypto` in `AuthConfig` or `WebAuthConfig` for PKCE/state/nonce generation. The SDK never installs globals or falls back to insecure randomness. Tests can inject storage, HTTP, and Web Crypto independently.

Git dependencies build the package through the standard `prepare` script. Package versions follow the existing release process; feature branches do not change the release version.

浏览器应用属于 OAuth public client，不要把 `client_secret` 放进前端代码。
