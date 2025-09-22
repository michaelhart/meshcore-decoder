// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AckPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class AckPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): AckPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Based on MeshCore payloads.md - Ack payload structure:
      // - checksum (4 bytes) - CRC checksum of message timestamp, text, and sender pubkey
      
      if (payload.length < 4) {
        const result: AckPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Ack,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Ack payload too short (minimum 4 bytes for checksum)'],
          checksum: ''
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Ack Data',
            description: 'Ack payload too short (minimum 4 bytes required for checksum)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;

      // parse checksum (4 bytes as hex)
      const checksum = bytesToHex(payload.subarray(0, 4));
      if (options?.includeSegments) {
        segments.push({
          name: 'Checksum',
          description: `CRC checksum of message timestamp, text, and sender pubkey: 0x${checksum}`,
          startByte: segmentOffset,
          endByte: segmentOffset + 3,
          value: checksum
        });
      }

      // any additional data (if present)
      if (options?.includeSegments && payload.length > 4) {
        segments.push({
          name: 'Additional Data',
          description: 'Extra data in Ack payload',
          startByte: segmentOffset + 4,
          endByte: segmentOffset + payload.length - 1,
          value: bytesToHex(payload.subarray(4))
        });
      }

      const result: AckPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Ack,
        version: PayloadVersion.Version1,
        isValid: true,
        checksum
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
    } catch (error) {
      return {
        type: PayloadType.Ack,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode Ack payload'],
        checksum: ''
      };
    }
  }
}
