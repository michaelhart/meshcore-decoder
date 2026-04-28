// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { CryptoKeyStore } from '../types/crypto';
import { ChannelCrypto } from './channel-crypto';

export class MeshCoreKeyStore implements CryptoKeyStore {
  public nodeKeys: Map<string, string> = new Map();
  
  // internal maps for hash prefix -> multiple keys (collision handling)
  private channelHashToKeys1 = new Map<string, string[]>();
  private channelHashToKeys2 = new Map<string, string[]>();

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
    if (normalizedHash.length === 2) {
      return this.channelHashToKeys1.has(normalizedHash);
    }
    if (normalizedHash.length === 4) {
      return this.channelHashToKeys2.has(normalizedHash);
    }
    return false;
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
    if (normalizedHash.length === 2) {
      return this.channelHashToKeys1.get(normalizedHash) || [];
    }
    if (normalizedHash.length === 4) {
      return this.channelHashToKeys2.get(normalizedHash) || [];
    }
    return [];
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
      const channelHash1 = ChannelCrypto.calculateChannelHash(secretKey, 1).toLowerCase();
      const channelHash2 = ChannelCrypto.calculateChannelHash(secretKey, 2).toLowerCase();

      if (!this.channelHashToKeys1.has(channelHash1)) {
        this.channelHashToKeys1.set(channelHash1, []);
      }
      this.channelHashToKeys1.get(channelHash1)!.push(secretKey);

      if (!this.channelHashToKeys2.has(channelHash2)) {
        this.channelHashToKeys2.set(channelHash2, []);
      }
      this.channelHashToKeys2.get(channelHash2)!.push(secretKey);
    }
  }
}
