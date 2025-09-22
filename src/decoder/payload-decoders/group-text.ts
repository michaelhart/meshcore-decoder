// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { GroupTextPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { DecryptionOptions } from '../../types/crypto';
import { ChannelCrypto } from '../../crypto/channel-crypto';
import { byteToHex, bytesToHex } from '../../utils/hex';

export class GroupTextPayloadDecoder {
  static decode(payload: Uint8Array, options?: DecryptionOptions): GroupTextPayload | null {
    try {
      if (payload.length < 3) {
        return {
          type: PayloadType.GroupText,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['GroupText payload too short (need at least channel_hash(1) + MAC(2))'],
          channelHash: '',
          cipherMac: '',
          ciphertext: '',
          ciphertextLength: 0
        };
      }

      // channel hash (1 byte) - first byte of SHA256 of channel's shared key
      const channelHash = byteToHex(payload[0]);
      
      // MAC (2 bytes) - message authentication code
      const cipherMac = bytesToHex(payload.subarray(1, 3));
      
      // ciphertext (remaining bytes) - encrypted message
      const ciphertext = bytesToHex(payload.subarray(3));

      const groupText: GroupTextPayload = {
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
