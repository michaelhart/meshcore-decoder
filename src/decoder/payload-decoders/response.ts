// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { ResponsePayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class ResponsePayloadDecoder {
  static decode(payload: Uint8Array): ResponsePayload | null {
    try {
      // Based on MeshCore payloads.md - Response payload structure:
      // - destination_hash (1 byte)
      // - source_hash (1 byte)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest of payload)
      
      if (payload.length < 4) {
        return {
          type: PayloadType.Response,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Response payload too short (minimum 4 bytes: dest + source + MAC)'],
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
        type: PayloadType.Response,
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
        type: PayloadType.Response,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode response payload'],
        destinationHash: '',
        sourceHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}