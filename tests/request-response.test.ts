// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MeshCorePacketDecoder, PayloadType, RequestType, RequestPayload, ResponsePayload, AnonRequestPayload, TextMessagePayload } from '../src';

const REQUEST_PACKET = '0200D1DEB01B2F8B72DD363AA4EF07E0BDA2266A8979';
const RESPONSE_PACKET = '0600DE1FDFCAD56E6C38B756FEE81C24199C6043AC5B';
const ANON_REQUEST_PACKET = '1E015F5754AF4E36FB37D58BE06A87AA8F97C23D0A1F42EC66ECED68875175540404A496141B071D2809885DE13090A8F813B9151927';
const TEXT_MESSAGE_PACKET = '09046F17C47ED00A13E16AB5B94B1CC2D1A5059C6E5A6253C60D';

describe('Request/Response/AnonRequest Packet Decoding', () => {
  describe('Request Packet', () => {
    it('should decode Request packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(REQUEST_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Request);
      expect(result.pathLength).toBe(0);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Request) {
        const requestPayload = result.payload.decoded as RequestPayload;
        
        // Verify request type (0x2F = 47)
        expect(requestPayload.requestType).toBe(RequestType.GetStats);
        
        // Verify request data
        expect(result.payload.raw).toBe('D1DEB01B2F8B72DD363AA4EF07E0BDA2266A8979');
      } else {
        fail('Request payload not decoded correctly');
      }
    });
  });

  describe('Response Packet', () => {
    it('should decode Response packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(RESPONSE_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Response);
      expect(result.pathLength).toBe(0);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Response) {
        const responsePayload = result.payload.decoded as ResponsePayload;
        
        // Validate Response payload structure with hex breakdown
        expect(responsePayload.destinationHash).toBe('DE'); // Byte 0: destination node hash
        expect(responsePayload.sourceHash).toBe('1F'); // Byte 1: source node hash
        expect(responsePayload.cipherMac).toBe('DFCA'); // Bytes 2-3: HMAC-SHA256 MAC (first 2 bytes)
        expect(responsePayload.ciphertext).toBe('D56E6C38B756FEE81C24199C6043AC5B'); // Bytes 4+: encrypted response data
        expect(responsePayload.ciphertextLength).toBe(16); // 32 hex chars = 16 bytes
      } else {
        fail('Response payload not decoded correctly');
      }
    });
  });

  describe('AnonRequest Packet', () => {
    it('should decode AnonRequest packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(ANON_REQUEST_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.AnonRequest);
      expect(result.pathLength).toBe(1);
      expect(result.path).toEqual(['5F']);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.AnonRequest) {
        const anonRequestPayload = result.payload.decoded as AnonRequestPayload;
        
        // Validate AnonRequest payload structure with hex breakdown
        expect(anonRequestPayload.destinationHash).toBe('57'); // Byte 0: destination node hash
        expect(anonRequestPayload.senderPublicKey).toBe('54AF4E36FB37D58BE06A87AA8F97C23D0A1F42EC66ECED68875175540404A496'); // Bytes 1-32: sender's Ed25519 public key
        expect(anonRequestPayload.cipherMac).toBe('141B'); // Bytes 33-34: HMAC-SHA256 MAC (first 2 bytes)
        expect(anonRequestPayload.ciphertext).toBe('071D2809885DE13090A8F813B9151927'); // Bytes 35+: encrypted request data
        expect(anonRequestPayload.ciphertextLength).toBe(16); // 32 hex chars = 16 bytes
      } else {
        fail('AnonRequest payload not decoded correctly');
      }
    });
  });

  describe('TextMessage Packet', () => {
    it('should decode TextMessage packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(TEXT_MESSAGE_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.TextMessage);
      expect(result.pathLength).toBe(4);
      expect(result.path).toEqual(['6F', '17', 'C4', '7E']);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.TextMessage) {
        const textMessagePayload = result.payload.decoded as TextMessagePayload;
        
        // Validate TextMessage payload structure with hex breakdown
        expect(textMessagePayload.destinationHash).toBe('D0'); // Byte 0: destination node hash
        expect(textMessagePayload.sourceHash).toBe('0A'); // Byte 1: source node hash
        expect(textMessagePayload.cipherMac).toBe('13E1'); // Bytes 2-3: HMAC-SHA256 MAC (first 2 bytes)
        expect(textMessagePayload.ciphertext).toBe('6AB5B94B1CC2D1A5059C6E5A6253C60D'); // Bytes 4+: encrypted message text
        expect(textMessagePayload.ciphertextLength).toBe(16); // 32 hex chars = 16 bytes
      } else {
        fail('TextMessage payload not decoded correctly');
      }
    });
  });
});