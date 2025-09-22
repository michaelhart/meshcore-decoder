// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { PathPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class PathPayloadDecoder {
  static decode(payload: Uint8Array): PathPayload | null {
    try {
      // Based on MeshCore payloads.md - Path payload structure:
      // - path_length (1 byte)
      // - path (variable length) - list of node hashes (one byte each)
      // - extra_type (1 byte) - bundled payload type
      // - extra (rest of data) - bundled payload content
      
      if (payload.length < 2) {
        return {
          type: PayloadType.Path,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Path payload too short (minimum 2 bytes: path length + extra type)'],
          pathLength: 0,
          pathHashes: [],
          extraType: 0,
          extraData: ''
        };
      }

      const pathLength = payload[0];
      
      if (payload.length < 1 + pathLength + 1) {
        return {
          type: PayloadType.Path,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: [`Path payload too short (need ${1 + pathLength + 1} bytes for path length + path + extra type)`],
          pathLength,
          pathHashes: [],
          extraType: 0,
          extraData: ''
        };
      }

      // Parse path hashes (one byte each)
      const pathHashes: string[] = [];
      for (let i = 0; i < pathLength; i++) {
        pathHashes.push(byteToHex(payload[1 + i]));
      }

      // Parse extra type (1 byte after path)
      const extraType = payload[1 + pathLength];

      // Parse extra data (remaining bytes)
      let extraData = '';
      if (payload.length > 1 + pathLength + 1) {
        extraData = bytesToHex(payload.subarray(1 + pathLength + 1));
      }

      return {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: true,
        pathLength,
        pathHashes,
        extraType,
        extraData
      };
    } catch (error) {
      return {
        type: PayloadType.Path,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode Path payload'],
        pathLength: 0,
        pathHashes: [],
        extraType: 0,
        extraData: ''
      };
    }
  }
}
