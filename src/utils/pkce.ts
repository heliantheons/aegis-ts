/**
 * PKCE (Proof Key for Code Exchange) 工具
 * RFC 7636: https://tools.ietf.org/html/rfc7636
 */

import type { PKCEParams } from "../types";

/**
 * 生成加密安全的随机字节
 */
function getRandomBytes(
  length: number,
  provider: Crypto | undefined,
): Uint8Array {
  if (!provider?.getRandomValues)
    throw new Error("Secure Web Crypto is required");
  const array = new Uint8Array(length);
  provider.getRandomValues(array);
  return array;
}

/**
 * Base64 URL 编码（不带 padding）
 */
function base64UrlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * 生成 code_verifier
 * 43-128 个字符，由 [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~" 组成
 */
export function generateCodeVerifier(
  length: number = 64,
  provider = globalThis.crypto,
): string {
  const validLength = Math.max(43, Math.min(128, length));
  const bytes = getRandomBytes(validLength, provider);
  return base64UrlEncode(bytes).slice(0, validLength);
}

/**
 * 生成 code_challenge（S256 方法）
 * code_challenge = BASE64URL(SHA256(code_verifier))
 */
export async function generateCodeChallenge(
  codeVerifier: string,
  provider = globalThis.crypto,
): Promise<string> {
  if (!provider?.subtle) throw new Error("Secure Web Crypto is required");
  const data = new TextEncoder().encode(codeVerifier);
  const hash = await provider.subtle.digest("SHA-256", data);
  return base64UrlEncode(hash);
}

/**
 * 生成完整的 PKCE 参数
 */
export async function generatePKCE(
  verifierLength: number = 64,
  provider = globalThis.crypto,
): Promise<PKCEParams> {
  const codeVerifier = generateCodeVerifier(verifierLength, provider);
  const codeChallenge = await generateCodeChallenge(codeVerifier, provider);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
  };
}

/**
 * 验证 code_verifier 格式
 */
export function isValidCodeVerifier(verifier: string): boolean {
  if (verifier.length < 43 || verifier.length > 128) {
    return false;
  }
  // 只允许 unreserved characters
  return /^[A-Za-z0-9\-._~]+$/.test(verifier);
}
