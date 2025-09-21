// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { DecodedPacket } from '../types/packet';
import { RouteType, PayloadType, PayloadVersion } from '../types/enums';
import { DecryptionOptions, ValidationResult, CryptoKeyStore } from '../types/crypto';
import { MeshCoreKeyStore } from '../crypto/key-manager';
import { AdvertPayloadDecoder } from './payload-decoders/advert';
import { TracePayloadDecoder } from './payload-decoders/trace';
import { GroupTextPayloadDecoder } from './payload-decoders/group-text';

export class MeshCorePacketDecoder {
  /**
   * Decode a raw packet from hex string
   */
  static decode(hexData: string, options?: DecryptionOptions): DecodedPacket {
    const bytes = this.hexToBytes(hexData);
    if (bytes.length < 2) {
      return {
        messageHash: '',
        routeType: RouteType.Flood,
        payloadType: PayloadType.RawCustom,
        payloadVersion: PayloadVersion.Version1,
        pathLength: 0,
        path: null,
        payload: { raw: '', decoded: null },
        totalBytes: bytes.length,
        isValid: false,
        errors: ['Packet too short (minimum 2 bytes required)']
      };
    }

    try {
      let offset = 0;

      // parse header
      const header = bytes[0];
      const routeType = header & 0x03;
      const payloadType = (header >> 2) & 0x0F;
      const payloadVersion = (header >> 6) & 0x03;
      offset = 1;

      // handle transport codes
      let transportCodes: [number, number] | undefined;
      if (routeType === RouteType.TransportFlood || routeType === RouteType.TransportDirect) {
        if (bytes.length < offset + 4) {
          throw new Error('Packet too short for transport codes');
        }
        const code1 = bytes[offset] | (bytes[offset + 1] << 8);
        const code2 = bytes[offset + 2] | (bytes[offset + 3] << 8);
        transportCodes = [code1, code2];
        offset += 4;
      }

      // parse path
      if (bytes.length < offset + 1) {
        throw new Error('Packet too short for path length');
      }
      const pathLength = bytes[offset];
      offset += 1;

      if (bytes.length < offset + pathLength) {
        throw new Error('Packet too short for path data');
      }

      // convert path data to hex strings
      const pathBytes = bytes.subarray(offset, offset + pathLength);
      const path = pathLength > 0 ? Array.from(pathBytes).map(b => b.toString(16).padStart(2, '0')) : null;
      offset += pathLength;

      // extract payload
      const payloadBytes = bytes.subarray(offset);
      const payloadHex = Array.from(payloadBytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

      // decode payload based on type
      let decodedPayload = null;
      if (payloadType === PayloadType.Advert) {
        decodedPayload = AdvertPayloadDecoder.decode(payloadBytes);
      } else if (payloadType === PayloadType.Trace) {
        decodedPayload = TracePayloadDecoder.decode(payloadBytes, path);
      } else if (payloadType === PayloadType.GroupText) {
        decodedPayload = GroupTextPayloadDecoder.decode(payloadBytes, options);
      }

      // calculate message hash
      const messageHash = this.calculateMessageHash(bytes, routeType, payloadType, payloadVersion);

      return {
        messageHash,
        routeType,
        payloadType,
        payloadVersion,
        transportCodes,
        pathLength,
        path,
        payload: {
          raw: payloadHex,
          decoded: decodedPayload
        },
        totalBytes: bytes.length,
        isValid: true
      };

    } catch (error) {
      return {
        messageHash: '',
        routeType: RouteType.Flood,
        payloadType: PayloadType.RawCustom,
        payloadVersion: PayloadVersion.Version1,
        pathLength: 0,
        path: null,
        payload: { raw: '', decoded: null },
        totalBytes: bytes.length,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Unknown decoding error']
      };
    }
  }

  /**
   * Validate packet format without full decoding
   */
  static validate(hexData: string): ValidationResult {
    const bytes = this.hexToBytes(hexData);
    const errors: string[] = [];

    if (bytes.length < 2) {
      errors.push('Packet too short (minimum 2 bytes required)');
      return { isValid: false, errors };
    }

    try {
      let offset = 1; // Skip header

      // check transport codes
      const header = bytes[0];
      const routeType = header & 0x03;
      if (routeType === RouteType.TransportFlood || routeType === RouteType.TransportDirect) {
        if (bytes.length < offset + 4) {
          errors.push('Packet too short for transport codes');
        }
        offset += 4;
      }

      // check path length
      if (bytes.length < offset + 1) {
        errors.push('Packet too short for path length');
      } else {
        const pathLength = bytes[offset];
        offset += 1;
        
        if (bytes.length < offset + pathLength) {
          errors.push('Packet too short for path data');
        }
        offset += pathLength;
      }

      // check if we have payload data
      if (offset >= bytes.length) {
        errors.push('No payload data found');
      }

    } catch (error) {
      errors.push(error instanceof Error ? error.message : 'Validation error');
    }

    return { isValid: errors.length === 0, errors: errors.length > 0 ? errors : undefined };
  }

  /**
   * Calculate message hash for a packet
   */
  static calculateMessageHash(bytes: Uint8Array, routeType: number, payloadType: number, payloadVersion: number): string {
    // for TRACE packets, use the trace tag as hash
    if (payloadType === PayloadType.Trace && bytes.length >= 13) {
      let offset = 1;
      
      // skip transport codes if present
      if (routeType === RouteType.TransportFlood || routeType === RouteType.TransportDirect) {
        offset += 4;
      }
      
      // skip path data
      if (bytes.length > offset) {
        const pathLen = bytes[offset];
        offset += 1 + pathLen;
      }
      
      // extract trace tag
      if (bytes.length >= offset + 4) {
        const traceTag = (bytes[offset]) | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
        return (traceTag >>> 0).toString(16).padStart(8, '0').toUpperCase();
      }
    }

    // for other packets, create hash from constant parts
    const constantHeader = (payloadType << 2) | (payloadVersion << 6);
    let offset = 1;
    
    // skip transport codes if present
    if (routeType === RouteType.TransportFlood || routeType === RouteType.TransportDirect) {
      offset += 4;
    }
    
    // skip path data
    if (bytes.length > offset) {
      const pathLen = bytes[offset];
      offset += 1 + pathLen;
    }
    
    const payloadData = bytes.slice(offset);
    const hashInput = [constantHeader, ...Array.from(payloadData)];

    // generate hash
    let hash = 0;
    for (let i = 0; i < hashInput.length; i++) {
      hash = ((hash << 5) - hash + hashInput[i]) & 0xffffffff;
    }
    
    return (hash >>> 0).toString(16).padStart(8, '0').toUpperCase();
  }

  /**
   * Create a key store for decryption
   */
  static createKeyStore(initialKeys?: {
    channelSecrets?: string[];
    nodeKeys?: Record<string, string>;
  }): CryptoKeyStore {
    return new MeshCoreKeyStore(initialKeys);
  }

  private static hexToBytes(hex: string): Uint8Array {
    // clean hex string (remove spaces and ensure even length)
    const cleanHex = hex.replace(/\s+/g, '');
    if (cleanHex.length % 2 !== 0) {
      throw new Error('Invalid hex string: odd length');
    }
    
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      const byte = parseInt(cleanHex.substr(i, 2), 16);
      if (isNaN(byte)) {
        throw new Error(`Invalid hex string: invalid characters at position ${i}`);
      }
      bytes[i / 2] = byte;
    }
    return bytes;
  }
}
