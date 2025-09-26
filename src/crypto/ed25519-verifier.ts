// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import * as ed25519 from '@noble/ed25519';
import { createHash } from 'crypto';
import { hexToBytes, bytesToHex } from '../utils/hex';

// Set up SHA-512 for @noble/ed25519
(ed25519 as any).etc.sha512Sync = (message: Uint8Array) => createHash('sha512').update(message).digest();
(ed25519 as any).etc.sha512Async = (message: Uint8Array) => Promise.resolve(createHash('sha512').update(message).digest());

export class Ed25519SignatureVerifier {
  /**
   * Verify an Ed25519 signature for MeshCore advertisement packets
   * 
   * According to MeshCore protocol, the signed message for advertisements is:
   * timestamp (4 bytes LE) + flags (1 byte) + location (8 bytes LE, if present) + name (variable, if present)
   */
  static async verifyAdvertisementSignature(
    publicKeyHex: string,
    signatureHex: string,
    timestamp: number,
    appDataHex: string
  ): Promise<boolean> {
    try {
      // Convert hex strings to Uint8Arrays
      const publicKey = hexToBytes(publicKeyHex);
      const signature = hexToBytes(signatureHex);
      const appData = hexToBytes(appDataHex);
      
      // Construct the signed message according to MeshCore format
      const message = this.constructAdvertSignedMessage(publicKeyHex, timestamp, appData);
      
      // Verify the signature using noble-ed25519
      return await ed25519.verify(signature, message, publicKey);
    } catch (error) {
      console.error('Ed25519 signature verification failed:', error);
      return false;
    }
  }

  /**
   * Construct the signed message for MeshCore advertisements
   * According to MeshCore source (Mesh.cpp lines 242-248):
   * Format: public_key (32 bytes) + timestamp (4 bytes LE) + app_data (variable length)
   */
  private static constructAdvertSignedMessage(
    publicKeyHex: string,
    timestamp: number,
    appData: Uint8Array
  ): Uint8Array {
    const publicKey = hexToBytes(publicKeyHex);
    
    // Timestamp (4 bytes, little-endian)
    const timestampBytes = new Uint8Array(4);
    timestampBytes[0] = timestamp & 0xFF;
    timestampBytes[1] = (timestamp >> 8) & 0xFF;
    timestampBytes[2] = (timestamp >> 16) & 0xFF;
    timestampBytes[3] = (timestamp >> 24) & 0xFF;
    
    // Concatenate: public_key + timestamp + app_data
    const message = new Uint8Array(32 + 4 + appData.length);
    message.set(publicKey, 0);
    message.set(timestampBytes, 32);
    message.set(appData, 36);
    
    return message;
  }

  /**
   * Get a human-readable description of what was signed
   */
  static getSignedMessageDescription(
    publicKeyHex: string,
    timestamp: number,
    appDataHex: string
  ): string {
    return `Public Key: ${publicKeyHex} + Timestamp: ${timestamp} (${new Date(timestamp * 1000).toISOString()}) + App Data: ${appDataHex}`;
  }

  /**
   * Get the hex representation of the signed message for debugging
   */
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
