// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { TextMessagePayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class TextMessagePayloadDecoder {
  static decode(payload: Uint8Array): TextMessagePayload | null {
    try {
      // Based on MeshCore payloads.md - TextMessage payload structure:
      // - destination_hash (1 byte)
      // - source_hash (1 byte)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest of payload)
      
      if (payload.length < 4) {
        return {
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
      }

      const destinationHash = byteToHex(payload[0]);
      const sourceHash = byteToHex(payload[1]);
      const cipherMac = bytesToHex(payload.subarray(2, 4));
      const ciphertext = bytesToHex(payload.subarray(4));

      return {
        type: PayloadType.TextMessage,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash,
        sourceHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 4
      };
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
