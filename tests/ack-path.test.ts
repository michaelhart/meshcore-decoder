// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { MeshCorePacketDecoder, PayloadType, AckPayload, PathPayload } from '../src';

const ACK_PACKET = '0D04B891647EBB40BA70';
const PATH_PACKET = '2105F464C77E411279399EFE1942B8A3FFA10F54D9C602FF2C8CF4';

describe('Ack/Path Packet Decoding', () => {
  describe('Ack Packet', () => {
    it('should decode Ack packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(ACK_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Ack);
      expect(result.pathLength).toBe(4);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Ack) {
        const ackPayload = result.payload.decoded as AckPayload;
        
        expect(ackPayload.isValid).toBe(true);
        
        // Validate Ack payload structure with hex breakdown
        expect(ackPayload.checksum).toBe('BB40BA70'); // Bytes 0-3: CRC checksum as hex
      } else {
        fail('Ack payload not decoded correctly');
      }
    });
  });

  describe('Path Packet', () => {
    it('should decode Path packet structure correctly', () => {
      const result = MeshCorePacketDecoder.decode(PATH_PACKET);
      
      expect(result.isValid).toBe(true);
      expect(result.payloadType).toBe(PayloadType.Path);
      expect(result.pathLength).toBe(5); // 5 bytes in packet-level path
      expect(result.path).toEqual(['F4', '64', 'C7', '7E', '41']); // Packet-level path data
      expect(result.messageHash).toBe('A574CE1D');
      expect(result.totalBytes).toBe(27);
      
      if (result.payload.decoded && 'type' in result.payload.decoded && result.payload.decoded.type === PayloadType.Path) {
        const pathPayload = result.payload.decoded as PathPayload;
        
        expect(pathPayload.isValid).toBe(true);
        
        // Validate Path payload structure with hex breakdown
        expect(pathPayload.pathLength).toBe(18); // Byte 0: 0x12 = 18 path hashes in payload
        expect(pathPayload.pathHashes).toEqual([
          '79', '39', '9E', 'FE', '19', '42', 'B8', 'A3', 'FF',
          'A1', '0F', '54', 'D9', 'C6', '02', 'FF', '2C', '8C'
        ]); // Bytes 1-18: path hashes
        expect(pathPayload.extraType).toBe(244); // Byte 19: 0xF4 = 244
        expect(pathPayload.extraData).toBe(''); // No extra data after extraType
      } else {
        fail('Path payload not decoded correctly');
      }
    });
  });
});
