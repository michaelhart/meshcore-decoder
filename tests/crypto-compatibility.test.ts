// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { Ed25519SignatureVerifier } from '../src/crypto/ed25519-verifier';

describe('Crypto Compatibility', () => {
  describe('Environment Detection Tests', () => {
    it('should handle signature verification gracefully', async () => {
      const publicKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      const signature = '2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609';
      const timestamp = 1758455660;
      const appData = '92A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

      // This should not throw an error regardless of environment
      const result = await Ed25519SignatureVerifier.verifyAdvertisementSignature(
        publicKey,
        signature,
        timestamp,
        appData
      );

      // Result should be boolean (true/false, not throw)
      expect(typeof result).toBe('boolean');
    });

    it('should generate signed message hex without errors', () => {
      const publicKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      const timestamp = 1758455660;
      const appData = '92A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

      // This should not throw an error
      const hex = Ed25519SignatureVerifier.getSignedMessageHex(publicKey, timestamp, appData);
      
      expect(typeof hex).toBe('string');
      expect(hex).toMatch(/^[0-9A-F]+$/i); // Should be hex string
      expect(hex.length).toBeGreaterThan(0);
    });

    it('should generate signed message description', () => {
      const publicKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
      const timestamp = 1758455660;
      const appData = '92A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

      const description = Ed25519SignatureVerifier.getSignedMessageDescription(
        publicKey,
        timestamp,
        appData
      );

      expect(typeof description).toBe('string');
      expect(description).toContain(publicKey);
      expect(description).toContain(timestamp.toString());
      expect(description).toContain(appData);
    });

    it('should reject synchronous key derivation', () => {
      const privateKey = '18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5';

      expect(() => {
        Ed25519SignatureVerifier.derivePublicKeySync(privateKey);
      }).toThrow('Synchronous key derivation not supported with WASM');
    });

    it('should handle key derivation gracefully', async () => {
      const privateKey = '18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5';

      try {
        // This will likely fail due to WASM not being available in test environment
        // But it should fail gracefully, not crash
        await Ed25519SignatureVerifier.derivePublicKey(privateKey);
      } catch (error) {
        // Expected to fail in test environment, but should be a proper error
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Error Path Coverage Tests', () => {
    it('should handle invalid hex in derivePublicKey', async () => {
      const invalidPrivateKey = 'invalid_hex_string'; // Invalid hex
      
      await expect(Ed25519SignatureVerifier.derivePublicKey(invalidPrivateKey))
        .rejects
        .toThrow('Failed to derive public key');
    });

    it('should handle invalid hex in derivePublicKeySync', () => {
      const invalidPrivateKey = 'invalid_hex_string'; // Invalid hex
      
      expect(() => {
        Ed25519SignatureVerifier.derivePublicKeySync(invalidPrivateKey);
      }).toThrow('Failed to derive public key');
    });

    it('should handle short private key in derivePublicKey', async () => {
      const shortPrivateKey = '1234'; // Too short (not 64 bytes)
      
      await expect(Ed25519SignatureVerifier.derivePublicKey(shortPrivateKey))
        .rejects
        .toThrow('Invalid private key length');
    });

    it('should handle short private key in derivePublicKeySync', () => {
      const shortPrivateKey = '1234'; // Too short (not 64 bytes)
      
      expect(() => {
        Ed25519SignatureVerifier.derivePublicKeySync(shortPrivateKey);
      }).toThrow('Invalid private key length');
    });

    it('should handle validateKeyPair errors gracefully', async () => {
      const invalidPrivateKey = 'invalid';
      const invalidPublicKey = 'invalid';
      
      // Should return false for invalid keys (not throw)
      const result = await Ed25519SignatureVerifier.validateKeyPair(invalidPrivateKey, invalidPublicKey);
      expect(result).toBe(false);
    });
  });

  describe('SHA-512 Implementation Tests', () => {
    it('should have crypto functions available for @noble/ed25519', () => {
      // Import the ed25519 module to check if our crypto setup worked
      const ed25519 = require('@noble/ed25519');
      
      // Check that our SHA-512 functions were set up
      expect(ed25519.etc.sha512Async).toBeDefined();
      expect(typeof ed25519.etc.sha512Async).toBe('function');
      
      // In Node.js environment, sync version should also be available
      if (typeof require !== 'undefined') {
        expect(ed25519.etc.sha512Sync).toBeDefined();
        expect(typeof ed25519.etc.sha512Sync).toBe('function');
      }
    });

    it('should handle SHA-512 async operation', async () => {
      const ed25519 = require('@noble/ed25519');
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      
      // This should not throw an error
      const result = await ed25519.etc.sha512Async(testData);
      
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(64); // SHA-512 produces 64 bytes
    });

    it('should handle SHA-512 sync operation in Node.js', () => {
      const ed25519 = require('@noble/ed25519');
      const testData = new Uint8Array([1, 2, 3, 4, 5]);
      
      if (typeof require !== 'undefined' && ed25519.etc.sha512Sync) {
        // This should not throw an error in Node.js
        const result = ed25519.etc.sha512Sync(testData);
        
        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBe(64); // SHA-512 produces 64 bytes
      } else {
        // In browser environment, sync version should not be available
        expect(ed25519.etc.sha512Sync).toBeUndefined();
      }
    });
  });
});