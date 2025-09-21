// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { CryptoKeyStore } from '../types/crypto';
import { ChannelCrypto } from './channel-crypto';

export class MeshCoreKeyStore implements CryptoKeyStore {
  public nodeKeys: Map<string, string> = new Map();
  
  // internal map for hash -> multiple keys (collision handling)
  private channelHashToKeys = new Map<string, string[]>();

  constructor(initialKeys?: {
    channelSecrets?: string[];
    nodeKeys?: Record<string, string>;
  }) {
    if (initialKeys?.channelSecrets) {
      this.addChannelSecrets(initialKeys.channelSecrets);
    }
    
    if (initialKeys?.nodeKeys) {
      Object.entries(initialKeys.nodeKeys).forEach(([pubKey, privKey]) => {
        this.addNodeKey(pubKey, privKey);
      });
    }
  }

  addNodeKey(publicKey: string, privateKey: string): void {
    const normalizedPubKey = publicKey.toUpperCase();
    this.nodeKeys.set(normalizedPubKey, privateKey);
  }

  hasChannelKey(channelHash: string): boolean {
    const normalizedHash = channelHash.toLowerCase();
    return this.channelHashToKeys.has(normalizedHash);
  }

  hasNodeKey(publicKey: string): boolean {
    const normalizedPubKey = publicKey.toUpperCase();
    return this.nodeKeys.has(normalizedPubKey);
  }

  /**
   * Get all channel keys that match the given channel hash (handles collisions)
   */
  getChannelKeys(channelHash: string): string[] {
    const normalizedHash = channelHash.toLowerCase();
    return this.channelHashToKeys.get(normalizedHash) || [];
  }

  getNodeKey(publicKey: string): string | undefined {
    const normalizedPubKey = publicKey.toUpperCase();
    return this.nodeKeys.get(normalizedPubKey);
  }

  /**
   * Add channel keys by secret keys (new simplified API)
   * Automatically calculates channel hashes
   */
  addChannelSecrets(secretKeys: string[]): void {
    for (const secretKey of secretKeys) {
      const channelHash = ChannelCrypto.calculateChannelHash(secretKey).toLowerCase();
      
      // Handle potential hash collisions
      if (!this.channelHashToKeys.has(channelHash)) {
        this.channelHashToKeys.set(channelHash, []);
      }
      this.channelHashToKeys.get(channelHash)!.push(secretKey);
    }
  }
}
