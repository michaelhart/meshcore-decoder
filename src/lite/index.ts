// MeshCore Packet Decoder - Lite Version (Pure JS, No WASM)
// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

/**
 * LITE VERSION - Pure JavaScript, no WASM required
 * 
 * Use this module when you need:
 * - No WASM support (e.g., some embedded browsers, restricted environments)
 * - Insecure context support (HTTP pages where crypto.subtle is unavailable)
 * 
 * The main module works in browsers too (requires HTTPS for crypto.subtle).
 * 
 * What's different:
 * - Uses crypto-js SHA-512 instead of Web Crypto API
 * - No WASM = no auth token signing, no orlp key derivation
 * - All packet decoding and decryption still works
 */

// Configure @noble/ed25519 to use crypto-js SHA-512 BEFORE any other imports
import * as ed25519 from '@noble/ed25519';
import CryptoJS from 'crypto-js';

function sha512Pure(data: Uint8Array): Uint8Array {
  const wordArray = CryptoJS.lib.WordArray.create(data as unknown as number[]);
  const hash = CryptoJS.SHA512(wordArray);
  const hashBytes = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const word = hash.words[i] || 0;
    hashBytes[i * 4] = (word >>> 24) & 0xff;
    hashBytes[i * 4 + 1] = (word >>> 16) & 0xff;
    hashBytes[i * 4 + 2] = (word >>> 8) & 0xff;
    hashBytes[i * 4 + 3] = word & 0xff;
  }
  return hashBytes;
}

// Configure noble/ed25519 to use our pure JS SHA-512
// This makes it work in insecure contexts where crypto.subtle is unavailable
(ed25519 as any).etc.sha512Sync = sha512Pure;
(ed25519 as any).etc.sha512Async = async (data: Uint8Array) => sha512Pure(data);

// Re-export the configured ed25519 for direct use
export { ed25519 };

// Now import and re-export everything from the main module
// The packet decoder will use our configured ed25519

// Type exports
export type { DecodedPacket, PacketStructure, PacketSegment, PayloadSegment, HeaderBreakdown } from '../types/packet';
export type { 
  BasePayload, 
  AdvertPayload, 
  TracePayload, 
  GroupTextPayload, 
  RequestPayload, 
  TextMessagePayload, 
  AnonRequestPayload, 
  AckPayload, 
  PathPayload,
  ResponsePayload,
  ControlPayloadBase,
  ControlDiscoverReqPayload,
  ControlDiscoverRespPayload,
  ControlPayload,
  PayloadData 
} from '../types/payloads';
export type { CryptoKeyStore, DecryptionOptions, DecryptionResult, ValidationResult } from '../types/crypto';

// Enum exports
export { 
  RouteType, 
  PayloadType, 
  PayloadVersion, 
  DeviceRole, 
  AdvertFlags, 
  RequestType,
  ControlSubType
} from '../types/enums';

// Crypto exports (these use crypto-js, which works in insecure contexts)
export { MeshCoreKeyStore } from '../crypto/key-manager';
export { ChannelCrypto } from '../crypto/channel-crypto';

// Utility exports
export { hexToBytes, bytesToHex, byteToHex, numberToHex } from '../utils/hex';
export { 
  getRouteTypeName, 
  getPayloadTypeName, 
  getPayloadVersionName, 
  getDeviceRoleName, 
  getRequestTypeName,
  getControlSubTypeName
} from '../utils/enum-names';

// Import the packet decoder (it will use our configured ed25519)
import { MeshCorePacketDecoder as OriginalDecoder } from '../decoder/packet-decoder';

// Re-export the decoder
export { OriginalDecoder as MeshCorePacketDecoder };
export { OriginalDecoder as MeshCoreDecoder };

// Pure JS Ed25519 signature verifier for advertisements
// This replaces the one in ed25519-verifier.ts that may fall back to Web Crypto
import { hexToBytes, bytesToHex } from '../utils/hex';

export class Ed25519SignatureVerifier {
  /**
   * Verify an Ed25519 signature for MeshCore advertisement packets
   * Uses @noble/ed25519 with crypto-js SHA-512 (works in insecure contexts)
   */
  static async verifyAdvertisementSignature(
    publicKeyHex: string,
    signatureHex: string,
    timestamp: number,
    appDataHex: string
  ): Promise<boolean> {
    try {
      const publicKey = hexToBytes(publicKeyHex);
      const signature = hexToBytes(signatureHex);
      const appData = hexToBytes(appDataHex);
      
      const message = this.constructAdvertSignedMessage(publicKeyHex, timestamp, appData);
      return await ed25519.verify(signature, message, publicKey);
    } catch (error) {
      console.error('Ed25519 signature verification failed:', error);
      return false;
    }
  }

  private static constructAdvertSignedMessage(
    publicKeyHex: string,
    timestamp: number,
    appData: Uint8Array
  ): Uint8Array {
    const publicKey = hexToBytes(publicKeyHex);
    
    const timestampBytes = new Uint8Array(4);
    timestampBytes[0] = timestamp & 0xFF;
    timestampBytes[1] = (timestamp >> 8) & 0xFF;
    timestampBytes[2] = (timestamp >> 16) & 0xFF;
    timestampBytes[3] = (timestamp >> 24) & 0xFF;
    
    const message = new Uint8Array(32 + 4 + appData.length);
    message.set(publicKey, 0);
    message.set(timestampBytes, 32);
    message.set(appData, 36);
    
    return message;
  }

  static getSignedMessageHex(
    publicKeyHex: string,
    timestamp: number,
    appDataHex: string
  ): string {
    const appData = hexToBytes(appDataHex);
    const message = this.constructAdvertSignedMessage(publicKeyHex, timestamp, appData);
    return bytesToHex(message);
  }
}

// Convenience functions
export function decodePacket(hexData: string, options?: any) {
  return OriginalDecoder.decode(hexData, options);
}

export function analyzePacket(hexData: string, options?: any) {
  return OriginalDecoder.analyzeStructure(hexData, options);
}

export async function decodePacketWithVerification(hexData: string, options?: any) {
  return OriginalDecoder.decodeWithVerification(hexData, options);
}

/**
 * Check if we're in a secure context (HTTPS or localhost)
 */
export function isSecureContext(): boolean {
  if (typeof globalThis === 'undefined' || typeof (globalThis as any).window === 'undefined') {
    // Node.js environment
    return true;
  }
  // Browser environment
  return (globalThis as any).isSecureContext ?? false;
}

/**
 * Check if Web Crypto API is available
 */
export function hasWebCrypto(): boolean {
  return typeof globalThis !== 'undefined' && 
         globalThis.crypto !== undefined && 
         (globalThis.crypto as any).subtle !== undefined;
}
