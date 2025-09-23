// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { RequestPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion, RequestType } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class RequestPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): RequestPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Based on MeshCore payloads.md - Request payload structure:
      // - destination hash (1 byte)
      // - source hash (1 byte)
      // - cipher MAC (2 bytes)
      // - ciphertext (rest of payload) - contains encrypted timestamp, request type, and request data
      
      if (payload.length < 4) {
        const result: RequestPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Request,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Request payload too short (minimum 4 bytes: dest hash + source hash + MAC)'],
          timestamp: 0,
          requestType: RequestType.GetStats,
          requestData: '',
          destinationHash: '',
          sourceHash: '',
          cipherMac: '',
          ciphertext: ''
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Request Data',
            description: 'Request payload too short (minimum 4 bytes required: 1 for dest hash + 1 for source hash + 2 for MAC)',
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
      const destinationHash = bytesToHex(payload.subarray(offset, offset + 1));
      
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

      // Parse source hash (1 byte)
      const sourceHash = bytesToHex(payload.subarray(offset, offset + 1));
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Source Hash',
          description: `First byte of source node public key: 0x${sourceHash}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: sourceHash
        });
      }
      offset += 1;

      // Parse cipher MAC (2 bytes)
      const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
      
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
      const ciphertext = bytesToHex(payload.subarray(offset));
      
      if (options?.includeSegments && payload.length > offset) {
        segments.push({
          name: 'Ciphertext',
          description: `Encrypted message data (${payload.length - offset} bytes). Contains encrypted plaintext with this structure:
• Timestamp (4 bytes) - send time as unix timestamp
• Request Type (1 byte) - type of request (GetStats, GetTelemetryData, etc.)
• Request Data (remaining bytes) - additional request-specific data`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const result: RequestPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Request,
        version: PayloadVersion.Version1,
        isValid: true,
        timestamp: 0, // Encrypted, cannot be parsed without decryption
        requestType: RequestType.GetStats, // Encrypted, cannot be determined without decryption
        requestData: '',
        destinationHash,
        sourceHash,
        cipherMac,
        ciphertext
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
    } catch (error) {
      return {
        type: PayloadType.Request,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode request payload'],
        timestamp: 0,
        requestType: RequestType.GetStats,
        requestData: '',
        destinationHash: '',
        sourceHash: '',
        cipherMac: '',
        ciphertext: ''
      };
    }
  }

}
