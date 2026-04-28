// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { GroupTextPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion } from '../../types/enums';
import { DecryptionOptions } from '../../types/crypto';
import { ChannelCrypto } from '../../crypto/channel-crypto';
import { byteToHex, bytesToHex } from '../../utils/hex';

interface GroupTextCandidate {
  channelHash: string;
  cipherMac: string;
  ciphertext: string;
  ciphertextLength: number;
  hashByteCount: 1 | 2;
}

function parseGroupTextCandidate(payload: Uint8Array, hashByteCount: 1 | 2): GroupTextCandidate | null {
  const minimumLength = hashByteCount + 2;
  if (payload.length < minimumLength) {
    return null;
  }

  let offset = 0;
  const channelHash = hashByteCount === 1
    ? byteToHex(payload[offset])
    : bytesToHex(payload.subarray(offset, offset + 2));
  offset += hashByteCount;

  const cipherMac = bytesToHex(payload.subarray(offset, offset + 2));
  offset += 2;

  const ciphertext = bytesToHex(payload.subarray(offset));

  return {
    channelHash,
    cipherMac,
    ciphertext,
    ciphertextLength: payload.length - minimumLength,
    hashByteCount
  };
}

export class GroupTextPayloadDecoder {
  static decode(payload: Uint8Array, options?: DecryptionOptions & { includeSegments?: boolean; segmentOffset?: number }): GroupTextPayload & { segments?: PayloadSegment[] } | null {
    try {
      const mode = options?.groupTextChannelHashBytes ?? 'auto';
      const minimumLength = mode === 2 ? 4 : 3;

      if (payload.length < minimumLength) {
        const result: GroupTextPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.GroupText,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: [
            mode === 2
              ? 'GroupText payload too short (need at least channel_hash(2) + MAC(2))'
              : 'GroupText payload too short (need at least channel_hash(1) + MAC(2))'
          ],
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
      const candidates: GroupTextCandidate[] = [];
      const requestedOrder: Array<1 | 2> =
        mode === 1 ? [1] :
        mode === 2 ? [2] :
        [1, 2];

      for (const hashByteCount of requestedOrder) {
        const candidate = parseGroupTextCandidate(payload, hashByteCount);
        if (candidate) {
          candidates.push(candidate);
        }
      }

      if (candidates.length === 0) {
        throw new Error('Failed to parse GroupText payload');
      }

      let selected = candidates[0];

      const groupText: GroupTextPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.GroupText,
        version: PayloadVersion.Version1,
        isValid: true,
        channelHash: selected.channelHash,
        cipherMac: selected.cipherMac,
        ciphertext: selected.ciphertext,
        ciphertextLength: selected.ciphertextLength
      };

      // attempt decryption if key store is provided
      if (options?.keyStore) {
        for (const candidate of candidates) {
          const channelKeys = options.keyStore.getChannelKeys(candidate.channelHash);
          const fallbackKeys =
            candidate.hashByteCount === 2
              ? options.keyStore.getChannelKeys(candidate.channelHash.substring(0, 2))
              : [];
          const keysToTry = Array.from(new Set([...channelKeys, ...fallbackKeys]));

          for (const channelKey of keysToTry) {
            const decryptionResult = ChannelCrypto.decryptGroupTextMessage(
              candidate.ciphertext,
              candidate.cipherMac,
              channelKey
            );

            if (decryptionResult.success && decryptionResult.data) {
              selected = candidate;
              groupText.channelHash = candidate.channelHash;
              groupText.cipherMac = candidate.cipherMac;
              groupText.ciphertext = candidate.ciphertext;
              groupText.ciphertextLength = candidate.ciphertextLength;
              groupText.decrypted = {
                timestamp: decryptionResult.data.timestamp,
                flags: decryptionResult.data.flags,
                sender: decryptionResult.data.sender,
                message: decryptionResult.data.message
              };
              break;
            }
          }

          if (groupText.decrypted) {
            break;
          }
        }
      }

      if (options?.includeSegments) {
        const hashDescription = selected.hashByteCount === 2
          ? 'First 2 bytes of SHA256 of channel\'s shared key'
          : 'First byte of SHA256 of channel\'s shared key';

        segments.push({
          name: 'Channel Hash',
          description: hashDescription,
          startByte: segmentOffset,
          endByte: segmentOffset + selected.hashByteCount - 1,
          value: selected.channelHash
        });

        const macStart = selected.hashByteCount;
        segments.push({
          name: 'Cipher MAC',
          description: 'MAC for encrypted data',
          startByte: segmentOffset + macStart,
          endByte: segmentOffset + macStart + 1,
          value: selected.cipherMac
        });

        if (payload.length > selected.hashByteCount + 2) {
          const ciphertextStart = selected.hashByteCount + 2;
          segments.push({
            name: 'Ciphertext',
            description: 'Encrypted message content (timestamp + flags + message)',
            startByte: segmentOffset + ciphertextStart,
            endByte: segmentOffset + payload.length - 1,
            value: selected.ciphertext
          });
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
