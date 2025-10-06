// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { sign, verify } from '../crypto/orlp-ed25519-wasm';
import { bytesToHex, hexToBytes } from './hex';

/**
 * JWT-style token payload for MeshCore authentication
 */
export interface AuthTokenPayload {
  /** Public key of the signer (32 bytes hex) */
  publicKey: string;
  /** Unix timestamp when token was issued */
  iat: number;
  /** Unix timestamp when token expires (optional) */
  exp?: number;
  /** Audience claim (optional) */
  aud?: string;
  /** Custom claims */
  [key: string]: any;
}

/**
 * Encoded auth token structure
 */
export interface AuthToken {
  /** Base64url-encoded header */
  header: string;
  /** Base64url-encoded payload */
  payload: string;
  /** Hex-encoded Ed25519 signature */
  signature: string;
}

/**
 * Base64url encode (URL-safe base64 without padding)
 */
function base64urlEncode(data: Uint8Array): string {
  // Convert to base64
  let base64 = '';
  if (typeof Buffer !== 'undefined') {
    // Node.js
    base64 = Buffer.from(data).toString('base64');
  } else {
    // Browser
    const binary = String.fromCharCode(...Array.from(data));
    base64 = btoa(binary);
  }
  
  // Make URL-safe and remove padding
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64url decode
 */
function base64urlDecode(str: string): Uint8Array {
  // Add padding back
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  
  if (typeof Buffer !== 'undefined') {
    // Node.js
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    // Browser
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Create a signed authentication token
 * 
 * @param payload - Token payload containing claims
 * @param privateKeyHex - 64-byte private key in hex format (orlp/ed25519 format)
 * @param publicKeyHex - 32-byte public key in hex format
 * @returns JWT-style token string in format: header.payload.signature
 */
export async function createAuthToken(
  payload: AuthTokenPayload,
  privateKeyHex: string,
  publicKeyHex: string
): Promise<string> {
  // Create header
  const header = {
    alg: 'Ed25519',
    typ: 'JWT'
  };
  
  // Ensure publicKey is in the payload (normalize to uppercase)
  if (!payload.publicKey) {
    payload.publicKey = publicKeyHex.toUpperCase();
  } else {
    payload.publicKey = payload.publicKey.toUpperCase();
  }
  
  // Ensure iat is set
  if (!payload.iat) {
    payload.iat = Math.floor(Date.now() / 1000);
  }
  
  // Encode header and payload
  const headerJson = JSON.stringify(header);
  const payloadJson = JSON.stringify(payload);
  
  const headerBytes = new TextEncoder().encode(headerJson);
  const payloadBytes = new TextEncoder().encode(payloadJson);
  
  const headerEncoded = base64urlEncode(headerBytes);
  const payloadEncoded = base64urlEncode(payloadBytes);
  
  // Create signing input: header.payload
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  const signingInputBytes = new TextEncoder().encode(signingInput);
  const signingInputHex = bytesToHex(signingInputBytes);
  
  // Sign the input using the normalized public key from payload
  const signatureHex = await sign(signingInputHex, privateKeyHex, payload.publicKey);
  
  // Return token in JWT format: header.payload.signature
  // Note: We use hex for signature instead of base64url for consistency with MeshCore
  return `${headerEncoded}.${payloadEncoded}.${signatureHex}`;
}

/**
 * Verify and decode an authentication token
 * 
 * @param token - JWT-style token string
 * @param expectedPublicKeyHex - Expected public key in hex format (optional, will check against payload if provided)
 * @returns Decoded payload if valid, null if invalid
 */
export async function verifyAuthToken(
  token: string,
  expectedPublicKeyHex?: string
): Promise<AuthTokenPayload | null> {
  try {
    // Parse token
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    const [headerEncoded, payloadEncoded, signatureHex] = parts;
    
    // Decode header and payload
    const headerBytes = base64urlDecode(headerEncoded);
    const payloadBytes = base64urlDecode(payloadEncoded);
    
    const headerJson = new TextDecoder().decode(headerBytes);
    const payloadJson = new TextDecoder().decode(payloadBytes);
    
    const header = JSON.parse(headerJson);
    const payload: AuthTokenPayload = JSON.parse(payloadJson);
    
    // Validate header
    if (header.alg !== 'Ed25519' || header.typ !== 'JWT') {
      return null;
    }
    
    // Validate payload has required fields
    if (!payload.publicKey || !payload.iat) {
      return null;
    }
    
    // Check if expected public key matches
    if (expectedPublicKeyHex && payload.publicKey.toUpperCase() !== expectedPublicKeyHex.toUpperCase()) {
      return null;
    }
    
    // Check expiration if present
    if (payload.exp) {
      const now = Math.floor(Date.now() / 1000);
      if (now > payload.exp) {
        return null; // Token expired
      }
    }
    
    // Verify signature
    const signingInput = `${headerEncoded}.${payloadEncoded}`;
    const signingInputBytes = new TextEncoder().encode(signingInput);
    const signingInputHex = bytesToHex(signingInputBytes);
    
    const isValid = await verify(signatureHex, signingInputHex, payload.publicKey);
    
    if (!isValid) {
      return null;
    }
    
    return payload;
  } catch (error) {
    return null;
  }
}

/**
 * Parse a token without verifying (useful for debugging)
 * 
 * @param token - JWT-style token string
 * @returns Parsed token structure or null if invalid format
 */
export function parseAuthToken(token: string): AuthToken | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    return {
      header: parts[0],
      payload: parts[1],
      signature: parts[2]
    };
  } catch (error) {
    return null;
  }
}

/**
 * Decode token payload without verification (useful for debugging)
 * 
 * @param token - JWT-style token string
 * @returns Decoded payload or null if invalid format
 */
export function decodeAuthTokenPayload(token: string): AuthTokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    
    const payloadBytes = base64urlDecode(parts[1]);
    const payloadJson = new TextDecoder().decode(payloadBytes);
    return JSON.parse(payloadJson);
  } catch (error) {
    return null;
  }
}
