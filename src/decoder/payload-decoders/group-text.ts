// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { GroupTextPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { DecryptionOptions } from '../../types/crypto';
import { ChannelCrypto } from '../../crypto/channel-crypto';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class GroupTextPayloadDecoder {
  static decode(payload: Uint8Array, options?: DecryptionOptions & { includeSegments?: boolean; segmentOffset?: number }): GroupTextPayload & { segments?: PayloadSegment[] } | null {
    try {
      if (payload.length < 3) {
        const result: GroupTextPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.GroupText,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['GroupText payload too short (need at least channel_hash(1) + MAC(2))'],
          channelHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid GroupText Data',
            description: 'GroupText payload too short (minimum 3 bytes required)',
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

      // channel hash (1 byte) - first byte of SHA256 of channel's shared key
      const channelHash = byteToHex(payload[offset]);
      if (options?.includeSegments) {
        segments.push({
          name: 'Channel Hash',
          description: 'First byte of SHA256 of channel\'s shared key',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: channelHash
        });
      }
      offset += 1;
      
      // MAC (2 bytes) - message authentication code
      const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
      if (options?.includeSegments) {
        segments.push({
          name: 'Cipher MAC',
          description: 'MAC for encrypted data',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 1,
          value: cipherMac
        });
      }
      offset += 2;
      
      // ciphertext (remaining bytes) - encrypted message
      const ciphertext = bytesToHex(payload.subarray(offset));
      if (options?.includeSegments && payload.length > offset) {
        segments.push({
          name: 'Ciphertext',
          description: 'Encrypted message content (timestamp + flags + message)',
          startByte: segmentOffset + offset,
          endByte: segmentOffset + payload.length - 1,
          value: ciphertext
        });
      }

      const groupText: GroupTextPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.GroupText,
        version: PayloadVersion.Version1,
        isValid: true,
        channelHash,
        cipherMac,
        ciphertext,
        ciphertextLength: payload.length - 3
      };

      // attempt decryption if key store is provided
      if (options?.keyStore && options.keyStore.hasChannelKey(channelHash)) {
        // try all possible keys for this hash (handles collisions)
        const channelKeys = options.keyStore.getChannelKeys(channelHash);
        
        for (const channelKey of channelKeys) {
          const decryptionResult = ChannelCrypto.decryptGroupTextMessage(
            ciphertext,
            cipherMac,
            channelKey
          );
          
          if (decryptionResult.success && decryptionResult.data) {
            groupText.decrypted = {
              timestamp: decryptionResult.data.timestamp,
              flags: decryptionResult.data.flags,
              sender: decryptionResult.data.sender,
              message: decryptionResult.data.message
            };
            break; // stop trying keys once we find one that works
          }
        }
      }

      if (options?.includeSegments) {
        groupText.segments = segments;
      }

      return groupText;
    } catch (error) {
      return {
        type: PayloadType.GroupText,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode GroupText payload'],
        channelHash: '',
        cipherMac: '',
        ciphertext: '',
        ciphertextLength: 0
      };
    }
  }
}
