// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { Utils } from '../src';
import type { AuthTokenPayload } from '../src';

describe('MeshCore Authentication Token', () => {
  // Sample key pair for testing (from key-derivation.test.ts)
  const sampleKeyPair = {
    publicKey: "4852b69364572b52efa1b6bb3e6d0abed4f389a1cbfbb60a9bba2cce649caf0e",
    privateKey: "18469d6140447f77de13cd8d761e605431f52269fbff43b0925752ed9e6745435dc6a86d2568af8b70d3365db3f88234760c8ecc645ce469829bc45b65f1d5d5"
  };

  // Initialize WASM before running any tests
  beforeAll(async () => {
    // Trigger WASM initialization by calling derivePublicKey
    await Utils.derivePublicKey(sampleKeyPair.privateKey);
  });

  describe('Token Creation and Verification', () => {
    it('should create and verify a valid auth token', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user',
        action: 'onboard'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3);

      // Verify the token
      const verified = await Utils.verifyAuthToken(token);
      
      expect(verified).not.toBeNull();
      expect(verified?.publicKey.toLowerCase()).toBe(sampleKeyPair.publicKey.toLowerCase());
      expect(verified?.sub).toBe('test-user');
      expect(verified?.action).toBe('onboard');
      expect(verified?.iat).toBe(payload.iat);
    });

    it('should verify token with expected public key', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Verify with correct public key
      const verified = await Utils.verifyAuthToken(token, sampleKeyPair.publicKey);
      expect(verified).not.toBeNull();

      // Verify with wrong public key should fail
      const wrongPublicKey = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const verifiedWrong = await Utils.verifyAuthToken(token, wrongPublicKey);
      expect(verifiedWrong).toBeNull();
    });

    it('should handle token expiration', async () => {
      // Create expired token
      const expiredPayload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        exp: Math.floor(Date.now() / 1000) - 1800  // Expired 30 minutes ago
      };

      const expiredToken = await Utils.createAuthToken(
        expiredPayload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const verified = await Utils.verifyAuthToken(expiredToken);
      expect(verified).toBeNull(); // Should be null due to expiration

      // Create valid token with future expiration
      const validPayload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600 // Expires in 1 hour
      };

      const validToken = await Utils.createAuthToken(
        validPayload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const verifiedValid = await Utils.verifyAuthToken(validToken);
      expect(verifiedValid).not.toBeNull();
    });

    it('should automatically set iat if not provided', async () => {
      const beforeTime = Math.floor(Date.now() / 1000);
      
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        sub: 'test-user'
      } as any; // Cast to bypass TypeScript check

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const verified = await Utils.verifyAuthToken(token);
      const afterTime = Math.floor(Date.now() / 1000);
      
      expect(verified).not.toBeNull();
      expect(verified?.iat).toBeGreaterThanOrEqual(beforeTime);
      expect(verified?.iat).toBeLessThanOrEqual(afterTime);
    });

    it('should include custom claims in token', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'user-123',
        email: 'test@example.com',
        role: 'admin',
        permissions: ['read', 'write', 'delete'],
        metadata: {
          deviceId: 'device-456',
          location: 'US-West'
        }
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const verified = await Utils.verifyAuthToken(token);
      
      expect(verified).not.toBeNull();
      expect(verified?.sub).toBe('user-123');
      expect(verified?.email).toBe('test@example.com');
      expect(verified?.role).toBe('admin');
      expect(verified?.permissions).toEqual(['read', 'write', 'delete']);
      expect(verified?.metadata).toEqual({
        deviceId: 'device-456',
        location: 'US-West'
      });
    });
  });

  describe('Token Parsing', () => {
    it('should parse token structure', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const parsed = Utils.parseAuthToken(token);
      
      expect(parsed).not.toBeNull();
      expect(parsed?.header).toBeDefined();
      expect(parsed?.payload).toBeDefined();
      expect(parsed?.signature).toBeDefined();
      expect(parsed?.signature).toMatch(/^[0-9A-F]{128}$/i); // 64 bytes = 128 hex chars
    });

    it('should decode payload without verification', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user',
        action: 'onboard'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const decoded = Utils.decodeAuthTokenPayload(token);
      
      expect(decoded).not.toBeNull();
      expect(decoded?.publicKey.toLowerCase()).toBe(sampleKeyPair.publicKey.toLowerCase());
      expect(decoded?.sub).toBe('test-user');
      expect(decoded?.action).toBe('onboard');
    });

    it('should return null for invalid token format', () => {
      const invalidTokens = [
        'invalid',
        'invalid.token',
        'invalid.token.signature.extra',
        '',
        'a.b'
      ];

      for (const invalidToken of invalidTokens) {
        expect(Utils.parseAuthToken(invalidToken)).toBeNull();
        expect(Utils.decodeAuthTokenPayload(invalidToken)).toBeNull();
      }
    });
  });

  describe('Token Tampering Detection', () => {
    it('should reject token with modified payload', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user',
        role: 'user'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Tamper with the payload by changing 'user' to 'admin'
      const parts = token.split('.');
      const payloadDecoded = Utils.decodeAuthTokenPayload(token);
      
      // Modify the payload
      const tamperedPayload = { ...payloadDecoded, role: 'admin' };
      const tamperedPayloadJson = JSON.stringify(tamperedPayload);
      const tamperedPayloadBytes = new TextEncoder().encode(tamperedPayloadJson);
      
      // Re-encode (base64url)
      let base64 = '';
      if (typeof Buffer !== 'undefined') {
        base64 = Buffer.from(tamperedPayloadBytes).toString('base64');
      } else {
        const binary = String.fromCharCode(...Array.from(tamperedPayloadBytes));
        base64 = btoa(binary);
      }
      const tamperedPayloadEncoded = base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      
      // Create tampered token
      const tamperedToken = `${parts[0]}.${tamperedPayloadEncoded}.${parts[2]}`;
      
      // Verification should fail
      const verified = await Utils.verifyAuthToken(tamperedToken);
      expect(verified).toBeNull();
    });

    it('should reject token with modified signature', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Tamper with signature
      const parts = token.split('.');
      const tamperedSignature = 'DEADBEEF' + parts[2].substring(8);
      const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSignature}`;
      
      // Verification should fail
      const verified = await Utils.verifyAuthToken(tamperedToken);
      expect(verified).toBeNull();
    });

    it('should reject token signed by different key', async () => {
      // Create a different key pair
      const differentPrivateKey = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
      const differentPublicKey = await Utils.derivePublicKey(differentPrivateKey);

      const payload: AuthTokenPayload = {
        publicKey: differentPublicKey,
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user'
      };

      // Sign with different key
      const token = await Utils.createAuthToken(
        payload,
        differentPrivateKey,
        differentPublicKey
      );

      // Try to verify with original public key
      const verified = await Utils.verifyAuthToken(token, sampleKeyPair.publicKey);
      expect(verified).toBeNull();
    });
  });

  describe('Edge Cases', () => {
    it('should handle case-insensitive public key comparison', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey.toUpperCase(),
        iat: Math.floor(Date.now() / 1000),
        sub: 'test-user'
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Verify with lowercase public key
      const verified = await Utils.verifyAuthToken(token, sampleKeyPair.publicKey.toLowerCase());
      expect(verified).not.toBeNull();
    });

    it('should handle empty custom claims', async () => {
      const payload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: Math.floor(Date.now() / 1000)
      };

      const token = await Utils.createAuthToken(
        payload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const verified = await Utils.verifyAuthToken(token);
      expect(verified).not.toBeNull();
      expect(verified?.publicKey).toBeDefined();
      expect(verified?.iat).toBeDefined();
    });

    it('should reject malformed JSON in token', async () => {
      // Create a token with invalid JSON
      const invalidToken = 'eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.INVALID_JSON.0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
      
      const verified = await Utils.verifyAuthToken(invalidToken);
      expect(verified).toBeNull();
    });
  });

  describe('Real-World Onboarding Scenario', () => {
    it('should create and verify onboarding token with user signature', async () => {
      // Simulate user onboarding flow
      const userId = 'user-12345';
      const deviceId = 'device-67890';
      const timestamp = Math.floor(Date.now() / 1000);
      
      // User creates token with their private key
      const onboardingPayload: AuthTokenPayload = {
        publicKey: sampleKeyPair.publicKey,
        iat: timestamp,
        exp: timestamp + 300, // Valid for 5 minutes
        sub: userId,
        action: 'onboard',
        deviceId: deviceId,
        requestedPermissions: ['mesh.read', 'mesh.write']
      };

      // User signs the token with their private key
      const token = await Utils.createAuthToken(
        onboardingPayload,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Service receives token and verifies it
      // Service only has the user's public key
      const verified = await Utils.verifyAuthToken(token, sampleKeyPair.publicKey);
      
      expect(verified).not.toBeNull();
      expect(verified?.sub).toBe(userId);
      expect(verified?.action).toBe('onboard');
      expect(verified?.deviceId).toBe(deviceId);
      expect(verified?.requestedPermissions).toEqual(['mesh.read', 'mesh.write']);
      
      // Service can now cryptographically verify:
      // 1. The token was signed by the user's private key
      // 2. The user owns the public key they claim
      // 3. The token hasn't been tampered with
      // 4. The token hasn't expired
    });

    it('should verify multiple tokens from same user', async () => {
      const userId = 'user-12345';
      
      // User creates multiple tokens for different actions
      const token1 = await Utils.createAuthToken(
        {
          publicKey: sampleKeyPair.publicKey,
          iat: Math.floor(Date.now() / 1000),
          sub: userId,
          action: 'onboard'
        },
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      const token2 = await Utils.createAuthToken(
        {
          publicKey: sampleKeyPair.publicKey,
          iat: Math.floor(Date.now() / 1000),
          sub: userId,
          action: 'update-profile'
        },
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Both tokens should verify successfully
      const verified1 = await Utils.verifyAuthToken(token1, sampleKeyPair.publicKey);
      const verified2 = await Utils.verifyAuthToken(token2, sampleKeyPair.publicKey);
      
      expect(verified1).not.toBeNull();
      expect(verified2).not.toBeNull();
      expect(verified1?.action).toBe('onboard');
      expect(verified2?.action).toBe('update-profile');
    });
  });

  describe('Low-Level Sign and Verify', () => {
    it('should sign and verify raw messages', async () => {
      const message = 'Hello, MeshCore!';
      const messageBytes = new TextEncoder().encode(message);
      const messageHex = Utils.bytesToHex(messageBytes);


      // Sign and verify
      const signature = await Utils.sign(
        messageHex,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      expect(signature).toBeDefined();
      expect(signature).toMatch(/^[0-9A-F]{128}$/i);

      const isValid = await Utils.verify(
        signature,
        messageHex,
        sampleKeyPair.publicKey
      );

      expect(isValid).toBe(true);
    });

    it('should reject invalid signatures', async () => {
      const message = 'Hello, MeshCore!';
      const messageBytes = new TextEncoder().encode(message);
      const messageHex = Utils.bytesToHex(messageBytes);

      // Sign the message
      const signature = await Utils.sign(
        messageHex,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Tamper with the signature
      const tamperedSignature = 'DEADBEEF' + signature.substring(8);

      // Verification should fail
      const isValid = await Utils.verify(
        tamperedSignature,
        messageHex,
        sampleKeyPair.publicKey
      );

      expect(isValid).toBe(false);
    });

    it('should reject signature with modified message', async () => {
      const message = 'Hello, MeshCore!';
      const messageBytes = new TextEncoder().encode(message);
      const messageHex = Utils.bytesToHex(messageBytes);

      // Sign the message
      const signature = await Utils.sign(
        messageHex,
        sampleKeyPair.privateKey,
        sampleKeyPair.publicKey
      );

      // Modify the message
      const modifiedMessage = 'Hello, MeshCore?';
      const modifiedMessageBytes = new TextEncoder().encode(modifiedMessage);
      const modifiedMessageHex = Utils.bytesToHex(modifiedMessageBytes);

      // Verification should fail
      const isValid = await Utils.verify(
        signature,
        modifiedMessageHex,
        sampleKeyPair.publicKey
      );

      expect(isValid).toBe(false);
    });
  });
});
