import { MeshCorePacketDecoder, RouteType, PayloadType, PayloadVersion, GroupTextPayload } from '../src';

describe('GroupText Decryption', () => {
  it('should decrypt public channel message from Tree', () => {
    const hexData = '150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';
    
    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [
        '8b3387e9c5cdea6ac9e5edbaa115cd72' // Public channel secret
      ]
    });
    
    const packet = MeshCorePacketDecoder.decode(hexData, { keyStore });
    
    // Basic packet structure
    expect(packet.isValid).toBe(true);
    expect(packet.routeType).toBe(RouteType.Flood);
    expect(packet.payloadType).toBe(PayloadType.GroupText);
    expect(packet.payloadVersion).toBe(PayloadVersion.Version1);
    
    // Payload should be decoded
    expect(packet.payload.decoded).toBeDefined();
    expect(packet.payload.decoded?.type).toBe(PayloadType.GroupText);
    
    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    
    // Validate GroupText payload structure with hex breakdown
    expect(groupText.channelHash).toBe('11'); // Byte 0: first byte of SHA256(channel_secret)
    expect(groupText.cipherMac).toBe('C3C1'); // Bytes 1-2: HMAC-SHA256 MAC (first 2 bytes)
    expect(groupText.ciphertext).toBe('354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D'); // Bytes 3+: AES-128 ECB encrypted message
    expect(groupText.ciphertextLength).toBe(32); // 64 hex chars = 32 bytes
    
    // Decryption should succeed
    expect(groupText.decrypted).toBeDefined();
    expect(groupText.decrypted?.sender).toBe('🌲 Tree');
    expect(groupText.decrypted?.message).toBe('☁️');
    expect(groupText.decrypted?.timestamp).toBe(1758484279); // Actual timestamp from decryption
  });

  it('should handle encrypted messages without keys', () => {
    const hexData = '150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';
    
    // No keyStore provided
    const packet = MeshCorePacketDecoder.decode(hexData);
    
    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.ciphertext).toBeDefined();
    expect(groupText.channelHash).toBe('11');
    expect(groupText.decrypted).toBeUndefined(); // No key available
  });

  it('should handle MAC verification failure with wrong key', () => {
    const hexData = '150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';
    
    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [
        'wrongkey1234567890abcdef12345678' // Wrong key
      ]
    });
    
    const packet = MeshCorePacketDecoder.decode(hexData, { keyStore });
    const groupText = packet.payload.decoded as GroupTextPayload;
    
    expect(groupText.decrypted).toBeUndefined(); // MAC verification should fail
  });

  it('should handle multiple channel secrets with same hash', () => {
    const hexData = '150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';
    
    // Test collision handling - multiple keys that might have same first byte
    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [
        'wrongkey1234567890abcdef12345678', // Wrong key (might have same hash)
        '8b3387e9c5cdea6ac9e5edbaa115cd72', // Correct public channel key
        'anotherwrongkey1234567890abcdef'   // Another wrong key
      ]
    });
    
    const packet = MeshCorePacketDecoder.decode(hexData, { keyStore });
    const groupText = packet.payload.decoded as GroupTextPayload;
    
    // Should still decrypt correctly
    expect(groupText.decrypted).toBeDefined();
    expect(groupText.decrypted?.sender).toBe('🌲 Tree');
    expect(groupText.decrypted?.message).toBe('☁️');
  });
});
