// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { HmacSHA256, AES, mode, pad, enc, lib, SHA256 } from 'crypto-js';
import { DecryptionResult } from '../types/crypto';
import { hexToBytes, bytesToHex } from '../utils/hex';

export class ChannelCrypto {
  /**
   * Decrypt GroupText message using MeshCore algorithm:
   * - HMAC-SHA256 verification with 2-byte MAC
   * - AES-128 ECB decryption
   */
  static decryptGroupTextMessage(
    ciphertext: string,
    cipherMac: string,
    channelKey: string
  ): DecryptionResult {
    try {
      // convert hex strings to byte arrays
      const channelKey16 = hexToBytes(channelKey);
      const macBytes = hexToBytes(cipherMac);
      
      // MeshCore uses 32-byte channel secret: 16-byte key + 16 zero bytes
      const channelSecret = new Uint8Array(32);
      channelSecret.set(channelKey16, 0);
      
      // Step 1: Verify HMAC-SHA256 using full 32-byte channel secret
      const calculatedMac = HmacSHA256(enc.Hex.parse(ciphertext), enc.Hex.parse(bytesToHex(channelSecret)));
      const calculatedMacBytes = hexToBytes(calculatedMac.toString(enc.Hex));
      const calculatedMacFirst2 = calculatedMacBytes.slice(0, 2);
      
      if (calculatedMacFirst2[0] !== macBytes[0] || calculatedMacFirst2[1] !== macBytes[1]) {
        return { success: false, error: 'MAC verification failed' };
      }
      
      // Step 2: Decrypt using AES-128 ECB with first 16 bytes of channel secret
      const keyWords = enc.Hex.parse(channelKey);
      const ciphertextWords = enc.Hex.parse(ciphertext);
      
      const decrypted = AES.decrypt(
        lib.CipherParams.create({ ciphertext: ciphertextWords }),
        keyWords,
        { mode: mode.ECB, padding: pad.NoPadding }
      );
      
      const decryptedBytes = hexToBytes(decrypted.toString(enc.Hex));
      
      if (!decryptedBytes || decryptedBytes.length < 5) {
        return { success: false, error: 'Decrypted content too short' };
      }
      
      // parse MeshCore format: timestamp(4) + flags(1) + message_text
      const timestamp = decryptedBytes[0] | 
                       (decryptedBytes[1] << 8) | 
                       (decryptedBytes[2] << 16) | 
                       (decryptedBytes[3] << 24);
      
      const flagsAndAttempt = decryptedBytes[4];
      
      // extract message text with UTF-8 decoding
      const messageBytes = decryptedBytes.slice(5);
      const decoder = new TextDecoder('utf-8');
      let messageText = decoder.decode(messageBytes);
      
      // remove null terminator if present
      const nullIndex = messageText.indexOf('\0');
      if (nullIndex >= 0) {
        messageText = messageText.substring(0, nullIndex);
      }

      // parse sender and message (format: "sender: message")
      const colonIndex = messageText.indexOf(': ');
      let sender: string | undefined;
      let content: string;

      if (colonIndex > 0 && colonIndex < 50) {
        const potentialSender = messageText.substring(0, colonIndex);
        if (!/[:\[\]]/.test(potentialSender)) {
          sender = potentialSender;
          content = messageText.substring(colonIndex + 2);
        } else {
          content = messageText;
        }
      } else {
        content = messageText;
      }

      return {
        success: true,
        data: {
          timestamp,
          flags: flagsAndAttempt,
          sender,
          message: content
        }
      };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Decryption failed' };
    }
  }



  /**
   * Calculate MeshCore channel hash from secret key
   * Returns the first byte of SHA256(secret) as hex string
   */
  static calculateChannelHash(secretKeyHex: string): string {
    const hash = SHA256(enc.Hex.parse(secretKeyHex));
    const hashBytes = hexToBytes(hash.toString(enc.Hex));
    return hashBytes[0].toString(16).padStart(2, '0');
  }
}
