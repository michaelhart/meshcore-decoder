// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { Utils } from '../src';

describe('MeshCore Ed25519 Key Derivation', () => {
  const sampleKeyPair = {
    "public_key": "4852b69364572b52efa1b6bb3e6d0abed4f389a1cbfbb60a9bba2cce649caf0e",
    "private_key": "18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5"
  };

  describe('Utils.derivePublicKey', () => {
    it('should derive correct public key from MeshCore private key', async () => {
      const derivedPublicKey = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      // Should match the expected public key (case insensitive)
      expect(derivedPublicKey.toLowerCase()).toBe(sampleKeyPair.public_key.toLowerCase());
    });

    it('should return 32-byte hex string', async () => {
      const derivedPublicKey = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      expect(derivedPublicKey).toMatch(/^[0-9A-Fa-f]{64}$/); // 64 hex chars = 32 bytes
      expect(derivedPublicKey.length).toBe(64);
    });

    it('should handle uppercase and lowercase private keys consistently', async () => {
      const lowercaseKey = await Utils.derivePublicKey(sampleKeyPair.private_key.toLowerCase());
      const uppercaseKey = await Utils.derivePublicKey(sampleKeyPair.private_key.toUpperCase());
      
      expect(lowercaseKey.toLowerCase()).toBe(uppercaseKey.toLowerCase());
    });

    it('should reject private keys that are not 64 bytes', async () => {
      const shortKey = '18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e674543'; // 32 bytes
      
      await expect(Utils.derivePublicKey(shortKey))
        .rejects.toThrow('Invalid private key length: expected 64 bytes, got 32');
    });

    it('should reject empty private key', async () => {
      await expect(Utils.derivePublicKey(''))
        .rejects.toThrow('Invalid private key length: expected 64 bytes, got 0');
    });

    it('should reject invalid hex characters', async () => {
      const invalidHex = 'ZZZZZZ6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5';
      
      await expect(Utils.derivePublicKey(invalidHex))
        .rejects.toThrow('Invalid hex string');
    });
  });

  describe('Utils.validateKeyPair', () => {
    it('should validate matching key pairs', async () => {
      // First derive the public key to ensure we have the correct one
      const derivedPublicKey = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      const isValid = await Utils.validateKeyPair(sampleKeyPair.private_key, derivedPublicKey);
      expect(isValid).toBe(true);
    });

    it('should reject mismatched key pairs', async () => {
      const wrongPublicKey = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      
      const isValid = await Utils.validateKeyPair(sampleKeyPair.private_key, wrongPublicKey);
      expect(isValid).toBe(false);
    });

    it('should handle case insensitive validation', async () => {
      const derivedPublicKey = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      const isValidLower = await Utils.validateKeyPair(sampleKeyPair.private_key, derivedPublicKey.toLowerCase());
      const isValidUpper = await Utils.validateKeyPair(sampleKeyPair.private_key, derivedPublicKey.toUpperCase());
      
      expect(isValidLower).toBe(true);
      expect(isValidUpper).toBe(true);
    });

    it('should return false for invalid private key format', async () => {
      const isValid = await Utils.validateKeyPair('invalid', sampleKeyPair.public_key);
      expect(isValid).toBe(false);
    });

    it('should return false for invalid public key format', async () => {
      const isValid = await Utils.validateKeyPair(sampleKeyPair.private_key, 'invalid');
      expect(isValid).toBe(false);
    });
  });

  describe('WASM Integration', () => {
    it('should consistently derive the same key multiple times', async () => {
      const key1 = await Utils.derivePublicKey(sampleKeyPair.private_key);
      const key2 = await Utils.derivePublicKey(sampleKeyPair.private_key);
      const key3 = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      expect(key1).toBe(key2);
      expect(key2).toBe(key3);
    });

    it('should work with orlp/ed25519 algorithm correctly', async () => {
      // This test verifies we're using the correct orlp/ed25519 algorithm
      // The sample data comes from a real MeshCore device
      const derivedKey = await Utils.derivePublicKey(sampleKeyPair.private_key);
      
      // Should match exactly what MeshCore produces
      expect(derivedKey.toLowerCase()).toBe(sampleKeyPair.public_key.toLowerCase());
    });
  });
});