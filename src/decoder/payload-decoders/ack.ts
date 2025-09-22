// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AckPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class AckPayloadDecoder {
  static decode(payload: Uint8Array): AckPayload | null {
    try {
      // Based on MeshCore payloads.md - Ack payload structure:
      // - checksum (4 bytes) - CRC checksum of message timestamp, text, and sender pubkey
      
      if (payload.length < 4) {
        return {
          type: PayloadType.Ack,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Ack payload too short (minimum 4 bytes for checksum)'],
          checksum: ''
        };
      }

      // Parse checksum (4 bytes as hex)
      const checksum = bytesToHex(payload.subarray(0, 4));

      return {
        type: PayloadType.Ack,
        version: PayloadVersion.Version1,
        isValid: true,
        checksum
      };
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
