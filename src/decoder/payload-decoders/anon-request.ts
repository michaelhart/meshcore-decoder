// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AnonRequestPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class AnonRequestPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): AnonRequestPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Based on MeshCore payloads.md - AnonRequest payload structure:
      // - destination_hash (1 byte)
      // - sender_public_key (32 bytes)
      // - cipher_mac (2 bytes)
      // - ciphertext (rest of payload)
      
      if (payload.length < 35) {
        const result: AnonRequestPayload & { segments?: PayloadSegment[] } = {
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
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid AnonRequest Data',
            description: 'AnonRequest payload too short (minimum 35 bytes required: 1 for dest hash + 32 for public key + 2 for MAC)',
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

      // Parse destination hash (1 byte)
      const destinationHash = byteToHex(payload[0]);
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Destination Hash',
          description: `First byte of destination node public key: 0x${destinationHash}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: destinationHash
        });
      }
      offset += 1;

      // Parse sender public key (32 bytes)
      const senderPublicKey = bytesToHex(payload.subarray(1, 33));
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Sender Public Key',
          description: `Ed25519 public key of the sender (32 bytes)`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 31,
          value: senderPublicKey
        });
      }
      offset += 32;

      // Parse cipher MAC (2 bytes)
      const cipherMac = bytesToHex(payload.subarray(33, 35));
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Cipher MAC',
          description: `MAC for encrypted data verification (2 bytes)`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 1,
          value: cipherMac
        });
      }
      offset += 2;

      // Parse ciphertext (remaining bytes)
      const ciphertext = bytesToHex(payload.subarray(35));
      
      if (options?.includeSegments && payload.length > 35) {
        segments.push({
          name: 'Ciphertext',
          description: `Encrypted message data (${payload.length - 35} bytes). Contains encrypted plaintext with this structure:
• Timestamp (4 bytes) - send time as unix timestamp
• Sync Timestamp (4 bytes) - room server only, sender's "sync messages SINCE x" timestamp  
• Password (remaining bytes) - password for repeater/room`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const result: AnonRequestPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.AnonRequest,
        version: PayloadVersion.Version1,
        isValid: true,
        destinationHash,
        senderPublicKey,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 35
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
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