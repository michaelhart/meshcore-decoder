// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AnonRequestPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class AnonRequestPayloadDecoder {
  static decode(payload: Uint8Array): AnonRequestPayload | null {
    try {
      // Based on MeshCore payloads.md - AnonRequest payload structure:
      // - destination_hash (1 byte)
      // - sender_public_key (32 bytes)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest of payload)
      
      if (payload.length < 35) {
        return {
          type: PayloadType.AnonRequest,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['AnonRequest payload too short (minimum 35 bytes: dest + public key + MAC)'],
          destinationHash: '',
          senderPublicKey: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };
      }

      const destinationHash = byteToHex(payload[0]);
      
      const senderPublicKey = bytesToHex(payload.subarray(1, 33));
      
      const cipherMac = bytesToHex(payload.subarray(33, 35));
      
      const ciphertext = bytesToHex(payload.subarray(35));

      return {
        type: PayloadType.AnonRequest,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash,
        senderPublicKey,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 35
      };
    } catch (error) {
      return {
        type: PayloadType.AnonRequest,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode AnonRequest payload'],
        destinationHash: '',
        senderPublicKey: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}