// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MeshCorePacketDecoder, PayloadType, RouteType } from '../src';

const ADVERT_PACKET = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';
const RESPONSE_PACKET = '0600DE1FDFCAD56E6C38B756FEE81C24199C6043AC5B';
const GROUPTEXT_PACKET = '150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';
const REQUEST_PACKET = '0200D1DEB01B2F8B72DD363AA4EF07E0BDA2266A8979';
const TEXT_MESSAGE_PACKET = '09046F17C47ED00A13E16AB5B94B1CC2D1A5059C6E5A6253C60D';

describe('Packet Structure Analysis', () => {
  describe('Header Breakdown', () => {
    it('should analyze Response packet header correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(RESPONSE_PACKET);
      
      expect(structure.totalBytes).toBe(22);
      expect(structure.segments).toHaveLength(3); // Header, Path Length, Payload
      
      // Header segment
      const headerSegment = structure.segments[0];
      expect(headerSegment.name).toBe('Header');
      expect(headerSegment.startByte).toBe(0);
      expect(headerSegment.endByte).toBe(0);
      expect(headerSegment.value).toBe('0x06');
      
      // Header breakdown
      expect(headerSegment.headerBreakdown).toBeDefined();
      expect(headerSegment.headerBreakdown!.fullBinary).toBe('00000110');
      expect(headerSegment.headerBreakdown!.fields).toHaveLength(3);
      
      const fields = headerSegment.headerBreakdown!.fields;
      expect(fields[0]).toEqual({
        bits: '0-1',
        field: 'Route Type',
        value: 'Direct',
        binary: '10'
      });
      expect(fields[1]).toEqual({
        bits: '2-5',
        field: 'Payload Type',
        value: 'Response',
        binary: '0001'
      });
      expect(fields[2]).toEqual({
        bits: '6-7',
        field: 'Version',
        value: '0',
        binary: '00'
      });
    });

    it('should analyze GroupText packet header correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(GROUPTEXT_PACKET);
      
      const headerSegment = structure.segments[0];
      expect(headerSegment.headerBreakdown!.fullBinary).toBe('00010101');
      
      const fields = headerSegment.headerBreakdown!.fields;
      expect(fields[0].value).toBe('Flood');
      expect(fields[1].value).toBe('GroupText');
      expect(fields[2].value).toBe('0');
    });
  });

  describe('Response Packet Structure', () => {
    it('should break down Response payload segments correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(RESPONSE_PACKET);
      
      expect(structure.payload.segments).toHaveLength(4);
      
      // Destination Hash
      expect(structure.payload.segments[0]).toEqual({
        name: 'Destination Hash',
        description: 'First byte of destination node public key',
        startByte: 0,
        endByte: 0,
        value: 'DE'
      });
      
      // Source Hash
      expect(structure.payload.segments[1]).toEqual({
        name: 'Source Hash',
        description: 'First byte of source node public key',
        startByte: 1,
        endByte: 1,
        value: '1F'
      });
      
      // Cipher MAC
      expect(structure.payload.segments[2]).toEqual({
        name: 'Cipher MAC',
        description: 'MAC for encrypted data in next field',
        startByte: 2,
        endByte: 3,
        value: 'DFCA'
      });
      
      // Ciphertext
      expect(structure.payload.segments[3]).toEqual({
        name: 'Ciphertext',
        description: 'Encrypted response data (tag + content)',
        startByte: 4,
        endByte: 19,
        value: 'D56E6C38B756FEE81C24199C6043AC5B'
      });
    });
  });

  describe('GroupText Packet Structure', () => {
    it('should break down GroupText payload segments correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(GROUPTEXT_PACKET);
      
      expect(structure.payload.segments).toHaveLength(3);
      
      // Channel Hash
      expect(structure.payload.segments[0]).toEqual({
        name: 'Channel Hash',
        description: 'First byte of SHA256 of channel\'s shared key',
        startByte: 0,
        endByte: 0,
        value: '11'
      });
      
      // Cipher MAC
      expect(structure.payload.segments[1]).toEqual({
        name: 'Cipher MAC',
        description: 'MAC for encrypted data',
        startByte: 1,
        endByte: 2,
        value: 'C3C1'
      });
      
      // Ciphertext
      const ciphertextSegment = structure.payload.segments[2];
      expect(ciphertextSegment.name).toBe('Ciphertext');
      expect(ciphertextSegment.description).toBe('Encrypted message content (timestamp + flags + message)');
      expect(ciphertextSegment.startByte).toBe(3);
      expect(ciphertextSegment.endByte).toBe(34);
      expect(ciphertextSegment.value).toBe('354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D');
    });
  });

  describe('TextMessage Packet Structure', () => {
    it('should break down TextMessage payload segments correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(TEXT_MESSAGE_PACKET);
      
      expect(structure.payload.segments).toHaveLength(4);
      
      // Destination Hash
      expect(structure.payload.segments[0]).toEqual({
        name: 'Destination Hash',
        description: 'First byte of destination node public key',
        startByte: 0,
        endByte: 0,
        value: 'D0'
      });
      
      // Source Hash
      expect(structure.payload.segments[1]).toEqual({
        name: 'Source Hash',
        description: 'First byte of source node public key',
        startByte: 1,
        endByte: 1,
        value: '0A'
      });
      
      // Cipher MAC
      expect(structure.payload.segments[2]).toEqual({
        name: 'Cipher MAC',
        description: 'MAC for encrypted data in next field',
        startByte: 2,
        endByte: 3,
        value: '13E1'
      });
      
      // Ciphertext
      expect(structure.payload.segments[3]).toEqual({
        name: 'Ciphertext',
        description: 'Encrypted message data (timestamp + message text)',
        startByte: 4,
        endByte: 19,
        value: '6AB5B94B1CC2D1A5059C6E5A6253C60D'
      });
    });
  });

  describe('Advert Packet Structure', () => {
    it('should break down Advert payload segments correctly', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(ADVERT_PACKET);
      
      expect(structure.payload.segments.length).toBeGreaterThanOrEqual(6); // At least: Public Key, Timestamp, Signature, App Flags, Latitude, Longitude, Node Name
      
      // Public Key (32 bytes)
      expect(structure.payload.segments[0]).toEqual({
        name: 'Public Key',
        description: 'Ed25519 public key',
        startByte: 0,
        endByte: 31,
        value: '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400'
      });
      
      // Timestamp (4 bytes)
      const timestampSegment = structure.payload.segments[1];
      expect(timestampSegment.name).toBe('Timestamp');
      expect(timestampSegment.startByte).toBe(32);
      expect(timestampSegment.endByte).toBe(35);
      expect(timestampSegment.value).toBe('6CE7CF68');
      expect(timestampSegment.description).toContain('1758455660'); // Unix timestamp
      expect(timestampSegment.description).toContain('2025-09-21T'); // ISO date
      
      // Signature (64 bytes)
      expect(structure.payload.segments[2]).toEqual({
        name: 'Signature',
        description: 'Ed25519 signature',
        startByte: 36,
        endByte: 99,
        value: '2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609'
      });
      
      // App Flags (1 byte)
      const flagsSegment = structure.payload.segments[3];
      expect(flagsSegment.name).toBe('App Flags');
      expect(flagsSegment.startByte).toBe(100);
      expect(flagsSegment.endByte).toBe(100);
      expect(flagsSegment.value).toBe('92');
      expect(flagsSegment.description).toContain('10010010'); // Binary representation
      
      // Should have location data (Latitude/Longitude) since HasLocation flag is set
      const latitudeSegment = structure.payload.segments.find(s => s.name === 'Latitude');
      const longitudeSegment = structure.payload.segments.find(s => s.name === 'Longitude');
      expect(latitudeSegment).toBeDefined();
      expect(longitudeSegment).toBeDefined();
      
      // Should have node name since HasName flag is set
      const nodeNameSegment = structure.payload.segments.find(s => s.name === 'Node Name');
      expect(nodeNameSegment).toBeDefined();
      expect(nodeNameSegment!.description).toContain('WW7STR/PugetMesh Cougar');
    });
  });

  describe('Path Analysis', () => {
    it('should analyze path data for TextMessage packet', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(TEXT_MESSAGE_PACKET);
      
      // Should have path length and path data segments
      const pathLengthSegment = structure.segments.find(s => s.name === 'Path Length');
      const pathDataSegment = structure.segments.find(s => s.name === 'Path Data');
      
      expect(pathLengthSegment).toBeDefined();
      expect(pathLengthSegment!.value).toBe('0x04'); // 4 bytes of path data
      
      expect(pathDataSegment).toBeDefined();
      expect(pathDataSegment!.value).toBe('6F17C47E'); // Path bytes
      expect(pathDataSegment!.description).toContain('Historical route taken');
    });

    it('should handle zero-length paths', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(RESPONSE_PACKET);
      
      const pathLengthSegment = structure.segments.find(s => s.name === 'Path Length');
      expect(pathLengthSegment).toBeDefined();
      expect(pathLengthSegment!.value).toBe('0x00');
      
      // Should not have path data segment for zero-length path
      const pathDataSegment = structure.segments.find(s => s.name === 'Path Data');
      expect(pathDataSegment).toBeUndefined();
    });
  });

  describe('Byte Range Accuracy', () => {
    it('should have accurate byte ranges for all segments', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(RESPONSE_PACKET);
      
      // Verify no gaps or overlaps in main segments
      let expectedByte = 0;
      for (const segment of structure.segments) {
        expect(segment.startByte).toBe(expectedByte);
        expectedByte = segment.endByte + 1;
      }
      
      // Verify payload segments don't overlap
      let payloadByte = 0;
      for (const segment of structure.payload.segments) {
        expect(segment.startByte).toBe(payloadByte);
        payloadByte = segment.endByte + 1;
      }
    });
  });

  describe('Error Handling', () => {
    it('should handle malformed packets gracefully', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure('05'); // Too short
      
      expect(structure.segments).toHaveLength(0);
      expect(structure.totalBytes).toBe(1);
      expect(structure.messageHash).toBe('');
      expect(structure.payload.segments).toHaveLength(0);
    });

    it('should handle truncated payload data', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure('0600DE1F'); // Response packet cut short
      
      // Should still parse header and path correctly
      expect(structure.segments.length).toBeGreaterThan(0);
      
      // Payload segments should handle truncated data gracefully
      expect(structure.payload.segments.length).toBeGreaterThan(0);
      const firstSegment = structure.payload.segments[0];
      expect(firstSegment.name).toBe('Invalid Response Data');
      expect(firstSegment.description).toContain('too short');
    });
  });

  describe('Hex Formatting', () => {
    it('should format all hex values in uppercase', () => {
      const structure = MeshCorePacketDecoder.analyzeStructure(GROUPTEXT_PACKET);
      
      // Check main segments (some have 0x prefix)
      for (const segment of structure.segments) {
        if (segment.name === 'Header' || segment.name === 'Path Length') {
          expect(segment.value).toMatch(/^0x[0-9A-F]+$/); // Header and Path Length have 0x prefix
        } else {
          expect(segment.value).toMatch(/^[0-9A-F]+$/); // Other segments are plain hex
        }
      }
      
      // Check payload segments
      for (const segment of structure.payload.segments) {
        expect(segment.value).toMatch(/^[0-9A-F]+$/); // Only uppercase hex
      }
      
      // Check raw hex
      expect(structure.rawHex).toMatch(/^[0-9A-F]+$/);
      expect(structure.payload.hex).toMatch(/^[0-9A-F]+$/);
    });
  });
});
