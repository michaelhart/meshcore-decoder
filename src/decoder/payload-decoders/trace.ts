// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { TracePayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';

export class TracePayloadDecoder {
  static decode(payload: Uint8Array, pathData?: string[] | null): TracePayload | null {
    try {
      if (payload.length < 9) {
        return {
          type: PayloadType.Trace,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Trace payload too short (need at least tag(4) + auth(4) + flags(1))'],
          traceTag: 0,
          authCode: 0,
          flags: 0,
          pathHashes: []
        };
      }

      let offset = 0;

      // Trace Tag (4 bytes) - unique identifier
      const traceTag = this.readUint32LE(payload, offset);
      offset += 4;

      // Auth Code (4 bytes) - authentication/verification code  
      const authCode = this.readUint32LE(payload, offset);
      offset += 4;

      // Flags (1 byte) - application-defined control flags
      const flags = payload[offset];
      offset += 1;

      // remaining bytes are path hashes (node hashes in the trace path)
      const pathHashes: string[] = [];
      while (offset < payload.length) {
        pathHashes.push(payload[offset].toString(16).padStart(2, '0'));
        offset++;
      }

      // extract SNR values from path field for TRACE packets
      let snrValues: number[] | undefined;
      if (pathData && pathData.length > 0) {
        snrValues = pathData.map(hexByte => {
          const byteValue = parseInt(hexByte, 16);
          // convert unsigned byte to signed int8 (SNR values are stored as signed int8 * 4)
          const snrSigned = byteValue > 127 ? byteValue - 256 : byteValue;
          return snrSigned / 4.0; // convert to dB
        });
      }

      return {
        type: PayloadType.Trace,
        version: PayloadVersion.Version1,
        isValid: true,
        traceTag,
        authCode,
        flags,
        pathHashes,
        snrValues
      };
    } catch (error) {
      return {
        type: PayloadType.Trace,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode trace payload'],
        traceTag: 0,
        authCode: 0,
        flags: 0,
        pathHashes: []
      };
    }
  }

  private static readUint32LE(buffer: Uint8Array, offset: number): number {
    return buffer[offset] |
      (buffer[offset + 1] << 8) |
      (buffer[offset + 2] << 16) |
      (buffer[offset + 3] << 24);
  }
}
