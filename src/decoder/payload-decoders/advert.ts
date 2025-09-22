// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AdvertPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion, DeviceRole, AdvertFlags } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class AdvertPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): AdvertPayload & { segments?: PayloadSegment[] } | null {
    try {
      // start of appdata section: public_key(32) + timestamp(4) + signature(64) + flags(1) = 101 bytes
      if (payload.length < 101) {
        const result: AdvertPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Advert,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Advertisement payload too short'],
          publicKey: '',
          timestamp: 0,
          signature: '',
          appData: {
            flags: 0,
            deviceRole: DeviceRole.ChatNode,
            hasLocation: false,
            hasName: false
          }
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Advert Data',
            description: 'Advert payload too short (minimum 101 bytes required)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;
      let currentOffset = 0;

      // parse advertisement structure from payloads.md
      const publicKey = bytesToHex(payload.subarray(currentOffset, currentOffset + 32));
      if (options?.includeSegments) {
        segments.push({
          name: 'Public Key',
          description: 'Ed25519 public key',
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 31,
          value: publicKey
        });
      }
      currentOffset += 32;
      
      const timestamp = this.readUint32LE(payload, currentOffset);
      if (options?.includeSegments) {
        const timestampDate = new Date(timestamp * 1000);
        segments.push({
          name: 'Timestamp',
          description: `${timestamp} (${timestampDate.toISOString().slice(0, 19)}Z)`,
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 3,
          value: bytesToHex(payload.subarray(currentOffset, currentOffset + 4))
        });
      }
      currentOffset += 4;
      
      const signature = bytesToHex(payload.subarray(currentOffset, currentOffset + 64));
      if (options?.includeSegments) {
        segments.push({
          name: 'Signature',
          description: 'Ed25519 signature',
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset + 63,
          value: signature
        });
      }
      currentOffset += 64;
      
      const flags = payload[currentOffset];
      if (options?.includeSegments) {
        const binaryStr = flags.toString(2).padStart(8, '0');
        const flagDesc = ` | Bit 4 (Location): ${!!(flags & AdvertFlags.HasLocation) ? 'Yes' : 'No'} | Bit 7 (Name): ${!!(flags & AdvertFlags.HasName) ? 'Yes' : 'No'}`;
        segments.push({
          name: 'App Flags',
          description: `Binary: ${binaryStr}${flagDesc}`,
          startByte: segmentOffset + currentOffset,
          endByte: segmentOffset + currentOffset,
          value: flags.toString(16).padStart(2, '0').toUpperCase()
        });
      }
      currentOffset += 1;

      const advert: AdvertPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Advert,
        version: PayloadVersion.Version1,
        isValid: true,
        publicKey,
        timestamp,
        signature,
        appData: {
          flags,
          deviceRole: this.parseDeviceRole(flags),
          hasLocation: !!(flags & AdvertFlags.HasLocation),
          hasName: !!(flags & AdvertFlags.HasName)
        }
      };

      let offset = currentOffset;

      // location data (if HasLocation flag is set)
      if (flags & AdvertFlags.HasLocation && payload.length >= offset + 8) {
        const lat = this.readInt32LE(payload, offset) / 1000000;
        const lon = this.readInt32LE(payload, offset + 4) / 1000000;
        advert.appData.location = {
          latitude: Math.round(lat * 1000000) / 1000000, // Keep precision
          longitude: Math.round(lon * 1000000) / 1000000
        };
        
        if (options?.includeSegments) {
          segments.push({
            name: 'Latitude',
            description: `${lat}° (${lat})`,
            startByte: segmentOffset + offset,
            endByte: segmentOffset + offset + 3,
            value: bytesToHex(payload.subarray(offset, offset + 4))
          });

          segments.push({
            name: 'Longitude',
            description: `${lon}° (${lon})`,
            startByte: segmentOffset + offset + 4,
            endByte: segmentOffset + offset + 7,
            value: bytesToHex(payload.subarray(offset + 4, offset + 8))
          });
        }
        
        offset += 8;
      }

      // skip feature fields for now (HasFeature1, HasFeature2)
      if (flags & AdvertFlags.HasFeature1) offset += 2;
      if (flags & AdvertFlags.HasFeature2) offset += 2;

      // name data (if HasName flag is set)
      if (flags & AdvertFlags.HasName && payload.length > offset) {
        const nameBytes = payload.subarray(offset);
        const rawName = new TextDecoder('utf-8').decode(nameBytes).replace(/\0.*$/, '');
        advert.appData.name = this.sanitizeControlCharacters(rawName) || rawName;
        
        if (options?.includeSegments) {
          segments.push({
            name: 'Node Name',
            description: `Node name: "${advert.appData.name}"`,
            startByte: segmentOffset + offset,
            endByte: segmentOffset + payload.length - 1,
            value: bytesToHex(nameBytes)
          });
        }
      }

      if (options?.includeSegments) {
        advert.segments = segments;
      }

      return advert;
    } catch (error) {
      return {
        type: PayloadType.Advert,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode advertisement payload'],
        publicKey: '',
        timestamp: 0,
        signature: '',
        appData: {
          flags: 0,
          deviceRole: DeviceRole.ChatNode,
          hasLocation: false,
          hasName: false
        }
      };
    }
  }

  private static parseDeviceRole(flags: number): DeviceRole {
    const roleValue = flags & 0x0F;
    switch (roleValue) {
      case 0x01: return DeviceRole.ChatNode;
      case 0x02: return DeviceRole.Repeater;
      case 0x03: return DeviceRole.RoomServer;
      case 0x04: return DeviceRole.Sensor;
      default: return DeviceRole.ChatNode;
    }
  }

  private static readUint32LE(buffer: Uint8Array, offset: number): number {
    return buffer[offset] |
      (buffer[offset + 1] << 8) |
      (buffer[offset + 2] << 16) |
      (buffer[offset + 3] << 24);
  }

  private static readInt32LE(buffer: Uint8Array, offset: number): number {
    const value = this.readUint32LE(buffer, offset);
    // convert unsigned to signed
    return value > 0x7FFFFFFF ? value - 0x100000000 : value;
  }

  private static sanitizeControlCharacters(value: string | null | undefined): string | null {
    if (!value) return null;
    const sanitized = value.trim().replace(/[\x00-\x1F\x7F]/g, '');
    return sanitized || null;
  }
}
