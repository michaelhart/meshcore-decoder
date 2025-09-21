// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { AdvertPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion, DeviceRole, AdvertFlags } from '../../types/enums';

export class AdvertPayloadDecoder {
  static decode(payload: Uint8Array): AdvertPayload | null {
    try {
      // start of appdata section: public_key(32) + timestamp(4) + signature(64) + flags(1) = 101 bytes
      if (payload.length < 101) {
        return {
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
      }

      // parse advertisement structure from payloads.md
      const publicKey = Array.from(payload.subarray(0, 32))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
      
      const timestamp = this.readUint32LE(payload, 32);
      
      const signature = Array.from(payload.subarray(36, 100))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
      
      const flags = payload[100];

      const advert: AdvertPayload = {
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

      let offset = 101;

      // location data (if HasLocation flag is set)
      if (flags & AdvertFlags.HasLocation && payload.length >= offset + 8) {
        const lat = this.readInt32LE(payload, offset) / 1000000;
        const lon = this.readInt32LE(payload, offset + 4) / 1000000;
        advert.appData.location = {
          latitude: Math.round(lat * 1000000) / 1000000, // Keep precision
          longitude: Math.round(lon * 1000000) / 1000000
        };
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
