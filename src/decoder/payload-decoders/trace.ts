// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { TracePayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { numberToHex, byteToHex, bytesToHex } from '../../utils/hex';

export class TracePayloadDecoder {
  static decode(payload: Uint8Array, pathData?: string[] | null, options?: { includeSegments?: boolean; segmentOffset?: number }): TracePayload & { segments?: PayloadSegment[] } | null {
    try {
      if (payload.length < 9) {
        const result: TracePayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Trace,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Trace payload too short (need at least tag(4) + auth(4) + flags(1))'],
          traceTag: '00000000',
          authCode: 0,
          flags: 0,
          pathHashes: []
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Trace Data',
            description: 'Trace payload too short (minimum 9 bytes required)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      let offset = 0;
      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;

      // Trace Tag (4 bytes) - unique identifier
      const traceTagRaw = this.readUint32LE(payload, offset);
      const traceTag = numberToHex(traceTagRaw, 8);
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Trace Tag',
          description: `Unique identifier for this trace: 0x${traceTagRaw.toString(16).padStart(8, '0')}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 3,
          value: bytesToHex(payload.slice(offset, offset + 4))
        });
      }
      offset += 4;

      // Auth Code (4 bytes) - authentication/verification code  
      const authCode = this.readUint32LE(payload, offset);
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Auth Code',
          description: `Authentication/verification code: ${authCode}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 3,
          value: bytesToHex(payload.slice(offset, offset + 4))
        });
      }
      offset += 4;

      // Flags (1 byte) - application-defined control flags
      const flags = payload[offset];
      
      if (options?.includeSegments) {
        segments.push({
          name: 'Flags',
          description: `Application-defined control flags: 0x${flags.toString(16).padStart(2, '0')} (${flags.toString(2).padStart(8, '0')}b)`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: flags.toString(16).padStart(2, '0').toUpperCase()
        });
      }
      offset += 1;

      // remaining bytes are path hashes (node hashes in the trace path)
      const pathHashes: string[] = [];
      const pathHashesStart = offset;
      while (offset < payload.length) {
        pathHashes.push(byteToHex(payload[offset]));
        offset++;
      }

      if (options?.includeSegments && pathHashes.length > 0) {
        const pathHashesDisplay = pathHashes.join(' ');
        segments.push({
          name: 'Path Hashes',
          description: `Node hashes in trace path: ${pathHashesDisplay}`,
          startByte: segmentOffset + pathHashesStart,
          endByte: segmentOffset + payload.length - 1,
          value: bytesToHex(payload.slice(pathHashesStart))
        });
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

      const result: TracePayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Trace,
        version: PayloadVersion.Version1,
        isValid: true,
        traceTag,
        authCode,
        flags,
        pathHashes,
        snrValues
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
    } catch (error) {
      return {
        type: PayloadType.Trace,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode trace payload'],
        traceTag: '00000000',
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
