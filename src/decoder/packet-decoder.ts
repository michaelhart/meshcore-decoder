// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { DecodedPacket, PacketStructure, PacketSegment, PayloadSegment, HeaderBreakdown } from '../types/packet';
import { RouteType, PayloadType, PayloadVersion } from '../types/enums';
import { hexToBytes, byteToHex, bytesToHex, numberToHex } from '../utils/hex';
import { getRouteTypeName, getPayloadTypeName } from '../utils/enum-names';
import { DecryptionOptions, ValidationResult, CryptoKeyStore } from '../types/crypto';
import { MeshCoreKeyStore } from '../crypto/key-manager';
import { AdvertPayloadDecoder } from './payload-decoders/advert';
import { TracePayloadDecoder } from './payload-decoders/trace';
import { GroupTextPayloadDecoder } from './payload-decoders/group-text';
import { RequestPayloadDecoder } from './payload-decoders/request';
import { ResponsePayloadDecoder } from './payload-decoders/response';
import { AnonRequestPayloadDecoder } from './payload-decoders/anon-request';
import { AckPayloadDecoder } from './payload-decoders/ack';
import { PathPayloadDecoder } from './payload-decoders/path';
import { TextMessagePayloadDecoder } from './payload-decoders/text-message';

export class MeshCorePacketDecoder {
  /**
   * Decode a raw packet from hex string
   */
  static decode(hexData: string, options?: DecryptionOptions): DecodedPacket {
    const result = this.parseInternal(hexData, false, options);
    return result.packet;
  }

  /**
   * Analyze packet structure for detailed breakdown
   */
  static analyzeStructure(hexData: string, options?: DecryptionOptions): PacketStructure {
    const result = this.parseInternal(hexData, true, options);
    return result.structure;
  }

  /**
   * Internal unified parsing method
   */
  private static parseInternal(hexData: string, includeStructure: boolean, options?: DecryptionOptions): {
    packet: DecodedPacket;
    structure: PacketStructure;
  } {
    const bytes = hexToBytes(hexData);
    const segments: PacketSegment[] = [];
    
    if (bytes.length < 2) {
      const errorPacket: DecodedPacket = {
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

      const errorStructure: PacketStructure = {
        segments: [],
        totalBytes: bytes.length,
        rawHex: hexData.toUpperCase(),
        messageHash: '',
        payload: {
          segments: [],
          hex: '',
          startByte: 0,
          type: 'Unknown'
        }
      };

      return { packet: errorPacket, structure: errorStructure };
    }

    try {
      let offset = 0;

      // parse header
      const header = bytes[0];
      const routeType = header & 0x03;
      const payloadType = (header >> 2) & 0x0F;
      const payloadVersion = (header >> 6) & 0x03;

      if (includeStructure) {
        segments.push({
          name: 'Header',
          description: 'Header byte breakdown',
          startByte: 0,
          endByte: 0,
          value: `0x${header.toString(16).padStart(2, '0')}`,
          headerBreakdown: {
            fullBinary: header.toString(2).padStart(8, '0'),
            fields: [
              {
                bits: '0-1',
                field: 'Route Type',
                value: getRouteTypeName(routeType),
                binary: (header & 0x03).toString(2).padStart(2, '0')
              },
              {
                bits: '2-5',
                field: 'Payload Type',
                value: getPayloadTypeName(payloadType),
                binary: ((header >> 2) & 0x0F).toString(2).padStart(4, '0')
              },
              {
                bits: '6-7',
                field: 'Version',
                value: payloadVersion.toString(),
                binary: ((header >> 6) & 0x03).toString(2).padStart(2, '0')
              }
            ]
          }
        });
      }
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

        if (includeStructure) {
          const transportCode = (bytes[offset]) | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
          segments.push({
            name: 'Transport Code',
            description: 'Used for Direct/Response routing',
            startByte: offset,
            endByte: offset + 3,
            value: `0x${transportCode.toString(16).padStart(8, '0')}`
          });
        }
        offset += 4;
      }

      // parse path
      if (bytes.length < offset + 1) {
        throw new Error('Packet too short for path length');
      }
      const pathLength = bytes[offset];

      if (includeStructure) {
        let pathLengthDescription = `Path contains ${pathLength} bytes`;
        if (routeType === RouteType.Direct || routeType === RouteType.TransportDirect) {
          pathLengthDescription = `For "Direct" packets, this contains routing instructions. ${pathLength} bytes of routing instructions (decreases as packet travels)`;
        } else if (routeType === RouteType.Flood || routeType === RouteType.TransportFlood) {
          pathLengthDescription = `${pathLength} bytes showing route taken (increases as packet floods)`;
        }

        segments.push({
          name: 'Path Length',
          description: pathLengthDescription,
          startByte: offset,
          endByte: offset,
          value: `0x${pathLength.toString(16).padStart(2, '0')}`
        });
      }
      offset += 1;

      if (bytes.length < offset + pathLength) {
        throw new Error('Packet too short for path data');
      }

      // convert path data to hex strings
      const pathBytes = bytes.subarray(offset, offset + pathLength);
      const path: string[] | null = pathLength > 0 ? Array.from(pathBytes).map(byteToHex) : null;

      if (includeStructure && pathLength > 0) {
        if (payloadType === PayloadType.Trace) {
          // TRACE packets have SNR values in path
          const snrValues = [];
          for (let i = 0; i < pathLength; i++) {
            const snrRaw = bytes[offset + i];
            const snrSigned = snrRaw > 127 ? snrRaw - 256 : snrRaw;
            const snrDb = snrSigned / 4.0;
            snrValues.push(`${snrDb.toFixed(2)}dB (0x${snrRaw.toString(16).padStart(2, '0')})`);
          }
          segments.push({
            name: 'Path SNR Data',
            description: `SNR values collected during trace: ${snrValues.join(', ')}`,
            startByte: offset,
            endByte: offset + pathLength - 1,
            value: bytesToHex(bytes.slice(offset, offset + pathLength))
          });
        } else {
          let pathDescription = 'Routing path information';
          if (routeType === RouteType.Direct || routeType === RouteType.TransportDirect) {
            pathDescription = 'Routing instructions (bytes are stripped at each hop as packet travels to destination)';
          } else if (routeType === RouteType.Flood || routeType === RouteType.TransportFlood) {
            pathDescription = 'Historical route taken (bytes are added as packet floods through network)';
          }

          segments.push({
            name: 'Path Data',
            description: pathDescription,
            startByte: offset,
            endByte: offset + pathLength - 1,
            value: bytesToHex(bytes.slice(offset, offset + pathLength))
          });
        }
      }
      offset += pathLength;

      // extract payload
      const payloadBytes = bytes.subarray(offset);
      const payloadHex = bytesToHex(payloadBytes);

      if (includeStructure && bytes.length > offset) {
        segments.push({
          name: 'Payload',
          description: `${getPayloadTypeName(payloadType)} payload data`,
          startByte: offset,
          endByte: bytes.length - 1,
          value: bytesToHex(bytes.slice(offset))
        });
      }

      // decode payload based on type and optionally get segments in one pass
      let decodedPayload = null;
      const payloadSegments: PayloadSegment[] = [];
      
      if (payloadType === PayloadType.Advert) {
        const result = AdvertPayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
      } else if (payloadType === PayloadType.Trace) {
        const result = TracePayloadDecoder.decode(payloadBytes, path as string[] | null, {
          includeSegments: includeStructure,
          segmentOffset: 0  // Payload segments are relative to payload start
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments; // Remove from decoded payload to keep it clean
        }
      } else if (payloadType === PayloadType.GroupText) {
        const result = GroupTextPayloadDecoder.decode(payloadBytes, {
          ...options,
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
      } else if (payloadType === PayloadType.Request) {
        decodedPayload = RequestPayloadDecoder.decode(payloadBytes);
      } else if (payloadType === PayloadType.Response) {
        const result = ResponsePayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0  // Payload segments are relative to payload start
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
      } else if (payloadType === PayloadType.AnonRequest) {
        decodedPayload = AnonRequestPayloadDecoder.decode(payloadBytes);
      } else if (payloadType === PayloadType.Ack) {
        const result = AckPayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
      } else if (payloadType === PayloadType.Path) {
        decodedPayload = PathPayloadDecoder.decode(payloadBytes);
      } else if (payloadType === PayloadType.TextMessage) {
        decodedPayload = TextMessagePayloadDecoder.decode(payloadBytes);
      }

      // if no segments were generated and we need structure, show basic payload info
      if (includeStructure && payloadSegments.length === 0 && bytes.length > offset) {
        payloadSegments.push({
            name: `${getPayloadTypeName(payloadType)} Payload`,
            description: `Raw ${getPayloadTypeName(payloadType)} payload data (${payloadBytes.length} bytes)`,
          startByte: 0,
          endByte: payloadBytes.length - 1,
          value: bytesToHex(payloadBytes)
        });
      }

      // calculate message hash
      const messageHash = this.calculateMessageHash(bytes, routeType, payloadType, payloadVersion);

      const packet: DecodedPacket = {
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

      const structure: PacketStructure = {
        segments,
        totalBytes: bytes.length,
        rawHex: hexData.toUpperCase(),
        messageHash,
        payload: {
          segments: payloadSegments,
          hex: payloadHex,
          startByte: offset,
          type: getPayloadTypeName(payloadType)
        }
      };

      return { packet, structure };

    } catch (error) {
      const errorPacket: DecodedPacket = {
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

      const errorStructure: PacketStructure = {
        segments: [],
        totalBytes: bytes.length,
        rawHex: hexData.toUpperCase(),
        messageHash: '',
        payload: {
          segments: [],
          hex: '',
          startByte: 0,
          type: 'Unknown'
        }
      };

      return { packet: errorPacket, structure: errorStructure };
    }
  }

  /**
   * Validate packet format without full decoding
   */
  static validate(hexData: string): ValidationResult {
    const bytes = hexToBytes(hexData);
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
        return numberToHex(traceTag, 8);
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
    
    return numberToHex(hash, 8);
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

}
