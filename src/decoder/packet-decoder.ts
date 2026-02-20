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
import { ControlPayloadDecoder } from './payload-decoders/control';

export class MeshCorePacketDecoder {
  /**
   * Decode a raw packet from hex string
   */
  static decode(hexData: string, options?: DecryptionOptions): DecodedPacket {
    const result = this.parseInternal(hexData, false, options);
    return result.packet;
  }

  /**
   * Decode a raw packet from hex string with signature verification for advertisements
   */
  static async decodeWithVerification(hexData: string, options?: DecryptionOptions): Promise<DecodedPacket> {
    const result = await this.parseInternalAsync(hexData, false, options);
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
   * Analyze packet structure for detailed breakdown with signature verification for advertisements
   */
  static async analyzeStructureWithVerification(hexData: string, options?: DecryptionOptions): Promise<PacketStructure> {
    const result = await this.parseInternalAsync(hexData, true, options);
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
        pathHashSize: 1,
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
          // MeshCore uses these as region transport codes: [0]=scope/region, [1]=return/home region
          segments.push({
            name: 'Region/Scope (transport code 0)',
            description: 'Region scope for this packet (repeaters match this to named regions, e.g. #Europe)',
            startByte: offset,
            endByte: offset + 1,
            value: `0x${(bytes[offset] | (bytes[offset + 1] << 8)).toString(16).padStart(4, '0')} (${code1})`
          });
          segments.push({
            name: 'Return region (transport code 1)',
            description: 'Sender\'s home/return region (used for replies)',
            startByte: offset + 2,
            endByte: offset + 3,
            value: `0x${(bytes[offset + 2] | (bytes[offset + 3] << 8)).toString(16).padStart(4, '0')} (${code2})`
          });
        }
        offset += 4;
      }

      // parse path length byte (encodes hash size and hop count)
      // Bits 7:6 = hash size selector: (path_len >> 6) + 1 = 1, 2, or 3 bytes per hop
      // Bits 5:0 = hop count (0-63)
      if (bytes.length < offset + 1) {
        throw new Error('Packet too short for path length');
      }
      const pathLenByte = bytes[offset];
      const { hashSize: pathHashSize, hopCount: pathHopCount, byteLength: pathByteLength } = this.decodePathLenByte(pathLenByte);

      if (pathHashSize === 4) {
        throw new Error('Invalid path length byte: reserved hash size (bits 7:6 = 11)');
      }

      if (includeStructure) {
        const hashDesc = pathHashSize > 1 ? ` × ${pathHashSize}-byte hashes (${pathByteLength} bytes)` : '';
        let pathLengthDescription: string;
        if (pathHopCount === 0) {
          pathLengthDescription = pathHashSize > 1 ? `No path data (${pathHashSize}-byte hash mode)` : 'No path data';
        } else if (routeType === RouteType.Direct || routeType === RouteType.TransportDirect) {
          pathLengthDescription = `${pathHopCount} hops${hashDesc} of routing instructions (decreases as packet travels)`;
        } else if (routeType === RouteType.Flood || routeType === RouteType.TransportFlood) {
          pathLengthDescription = `${pathHopCount} hops${hashDesc} showing route taken (increases as packet floods)`;
        } else {
          pathLengthDescription = `Path contains ${pathHopCount} hops${hashDesc}`;
        }

        segments.push({
          name: 'Path Length',
          description: pathLengthDescription,
          startByte: offset,
          endByte: offset,
          value: `0x${pathLenByte.toString(16).padStart(2, '0')}`,
          headerBreakdown: {
            fullBinary: pathLenByte.toString(2).padStart(8, '0'),
            fields: [
              {
                bits: '6-7',
                field: 'Hash Size',
                value: `${pathHashSize} byte${pathHashSize > 1 ? 's' : ''} per hop`,
                binary: ((pathLenByte >> 6) & 0x03).toString(2).padStart(2, '0')
              },
              {
                bits: '0-5',
                field: 'Hop Count',
                value: `${pathHopCount} hop${pathHopCount !== 1 ? 's' : ''}`,
                binary: (pathLenByte & 63).toString(2).padStart(6, '0')
              }
            ]
          }
        });
      }
      offset += 1;

      if (bytes.length < offset + pathByteLength) {
        throw new Error('Packet too short for path data');
      }

      // convert path data to grouped hex strings (one entry per hop)
      const pathBytes = bytes.subarray(offset, offset + pathByteLength);
      let path: string[] | null = null;
      if (pathHopCount > 0) {
        path = [];
        for (let i = 0; i < pathHopCount; i++) {
          const hopBytes = pathBytes.subarray(i * pathHashSize, (i + 1) * pathHashSize);
          path.push(bytesToHex(hopBytes));
        }
      }

      if (includeStructure && pathHopCount > 0) {
        if (payloadType === PayloadType.Trace) {
          // TRACE packets have SNR values in path (always single-byte entries)
          const snrValues = [];
          for (let i = 0; i < pathByteLength; i++) {
            const snrRaw = bytes[offset + i];
            const snrSigned = snrRaw > 127 ? snrRaw - 256 : snrRaw;
            const snrDb = snrSigned / 4.0;
            snrValues.push(`${snrDb.toFixed(2)}dB (0x${snrRaw.toString(16).padStart(2, '0')})`);
          }
          segments.push({
            name: 'Path SNR Data',
            description: `SNR values collected during trace: ${snrValues.join(', ')}`,
            startByte: offset,
            endByte: offset + pathByteLength - 1,
            value: bytesToHex(bytes.slice(offset, offset + pathByteLength))
          });
        } else {
          let pathDescription = 'Routing path information';
          if (routeType === RouteType.Direct || routeType === RouteType.TransportDirect) {
            pathDescription = `Routing instructions (${pathHashSize}-byte hashes stripped at each hop as packet travels to destination)`;
          } else if (routeType === RouteType.Flood || routeType === RouteType.TransportFlood) {
            pathDescription = `Historical route taken (${pathHashSize}-byte hashes added as packet floods through network)`;
          }

          segments.push({
            name: 'Path Data',
            description: pathDescription,
            startByte: offset,
            endByte: offset + pathByteLength - 1,
            value: bytesToHex(bytes.slice(offset, offset + pathByteLength))
          });
        }
      }
      offset += pathByteLength;

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
        const result = RequestPayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0  // Payload segments are relative to payload start
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
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
        const result = AnonRequestPayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
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
        const result = TextMessagePayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
      } else if (payloadType === PayloadType.Control) {
        const result = ControlPayloadDecoder.decode(payloadBytes, {
          includeSegments: includeStructure,
          segmentOffset: 0
        });
        decodedPayload = result;
        if (result?.segments) {
          payloadSegments.push(...result.segments);
          delete result.segments;
        }
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
        pathLength: pathHopCount,
        pathHashSize,
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
        pathHashSize: 1,
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
   * Internal unified parsing method with signature verification for advertisements
   */
  private static async parseInternalAsync(hexData: string, includeStructure: boolean, options?: DecryptionOptions): Promise<{
    packet: DecodedPacket;
    structure: PacketStructure;
  }> {
    // First do the regular parsing
    const result = this.parseInternal(hexData, includeStructure, options);
    
    // If it's an advertisement, verify the signature
    if (result.packet.payloadType === PayloadType.Advert && result.packet.payload.decoded) {
      try {
        const advertPayload = result.packet.payload.decoded as any;
        const verifiedAdvert = await AdvertPayloadDecoder.decodeWithVerification(
          hexToBytes(result.packet.payload.raw),
          {
            includeSegments: includeStructure,
            segmentOffset: 0
          }
        );
        
        if (verifiedAdvert) {
          // Update the payload with signature verification results
          result.packet.payload.decoded = verifiedAdvert;
          
          // If the advertisement signature is invalid, mark the whole packet as invalid
          if (!verifiedAdvert.isValid) {
            result.packet.isValid = false;
            result.packet.errors = verifiedAdvert.errors || ['Invalid advertisement signature'];
          }
          
          // Update structure segments if needed
          if (includeStructure && verifiedAdvert.segments) {
            result.structure.payload.segments = verifiedAdvert.segments;
            delete verifiedAdvert.segments;
          }
        }
      } catch (error) {
        console.error('Signature verification failed:', error);
      }
    }
    
    return result;
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
        const pathLenByte = bytes[offset];
        const { hashSize, byteLength } = this.decodePathLenByte(pathLenByte);
        offset += 1;

        if (hashSize === 4) {
          errors.push('Invalid path length byte: reserved hash size (bits 7:6 = 11)');
        }
        if (bytes.length < offset + byteLength) {
          errors.push('Packet too short for path data');
        }
        offset += byteLength;
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

      // skip path data (decode path_len byte for multi-byte hops)
      if (bytes.length > offset) {
        const { byteLength } = this.decodePathLenByte(bytes[offset]);
        offset += 1 + byteLength;
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

    // skip path data (decode path_len byte for multi-byte hops)
    if (bytes.length > offset) {
      const { byteLength } = this.decodePathLenByte(bytes[offset]);
      offset += 1 + byteLength;
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

  /**
   * Decode a path_len byte into hash size, hop count, and total byte length.
   * Firmware reference: Packet.h lines 79-83
   *   Bits 7:6 = hash size selector: (path_len >> 6) + 1 = 1, 2, or 3 bytes per hop
   *   Bits 5:0 = hop count (0-63)
   */
  private static decodePathLenByte(pathLenByte: number): { hashSize: number; hopCount: number; byteLength: number } {
    const hashSize = (pathLenByte >> 6) + 1;
    const hopCount = pathLenByte & 63;
    return { hashSize, hopCount, byteLength: hopCount * hashSize };
  }

}
