// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { TextMessagePayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class TextMessagePayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): TextMessagePayload & { segments?: PayloadSegment[] } | null {
    try {
      // Based on MeshCore payloads.md - TextMessage payload structure:
      // - destination_hash (1 byte)
      // - source_hash (1 byte)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest of payload)
      
      if (payload.length < 4) {
        const result: TextMessagePayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.TextMessage,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['TextMessage payload too short (minimum 4 bytes: dest + source + MAC)'],
          destinationHash: '',
          sourceHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid TextMessage Data',
            description: 'TextMessage payload too short (minimum 4 bytes required)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;
      let offset = 0;

      // Destination Hash (1 byte)
      const destinationHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Destination Hash',
          description: 'First byte of destination node public key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: destinationHash
        });
      }
      offset += 1;

      // Source Hash (1 byte)
      const sourceHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Source Hash',
          description: 'First byte of source node public key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: sourceHash
        });
      }
      offset += 1;

      // Cipher MAC (2 bytes)
      const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
      if (options?.includeSegments) {
        segments.push({
          name: 'Cipher MAC',
          description: 'MAC for encrypted data in next field',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 1,
          value: cipherMac
        });
      }
      offset += 2;

      // Ciphertext (remaining bytes)
      const ciphertext = bytesToHex(payload.subarray(offset));
      if (options?.includeSegments && payload.length > offset) {
        segments.push({
          name: 'Ciphertext',
          description: 'Encrypted message data (timestamp + message text)',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const result: TextMessagePayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.TextMessage,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash,
        sourceHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 4
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
    } catch (error) {
      return {
        type: PayloadType.TextMessage,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode TextMessage payload'],
        destinationHash: '',
        sourceHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}
