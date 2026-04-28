import { MeshCorePacketDecoder, RouteType, PayloadType, PayloadVersion, GroupTextPayload } from '../src';

// #bot channel key for multi-byte hop tests
const BOT_CHANNEL_KEY = 'eb50a1bcb3e4e5d7bf69a57c9dada211';

describe('Multi-byte Hop Labels', () => {
  it('should decode 3-byte hashes with 3 hops (path_len = 0x83)', () => {
    const hexData = '15833fa002860ccae0eed9ca78b9ab0775d477c1f6490a398bf4edc75240';

    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [BOT_CHANNEL_KEY]
    });

    const packet = MeshCorePacketDecoder.decode(hexData, { keyStore });

    expect(packet.isValid).toBe(true);
    expect(packet.routeType).toBe(RouteType.Flood);
    expect(packet.payloadType).toBe(PayloadType.GroupText);

    // Path encoding: 0x83 = hash_size=3, hop_count=3 (only set when > 1)
    expect(packet.pathHashSize).toBe(3);
    expect(packet.pathLength).toBe(3);
    expect(packet.path).toEqual(['3FA002', '860CCA', 'E0EED9']);

    // Should decrypt with #bot key
    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    expect(groupText.decrypted).toBeDefined();
    expect(groupText.decrypted?.sender).toBe('Roy B V4');
    expect(groupText.decrypted?.message).toBe('P');
  });

  it('should decode 2-byte hashes with 0 hops (path_len = 0x40)', () => {
    const hexData = '1540cab3b15626481a5ba64247ab25766e410b026e0678a32da9f0c3946fae5b714cab170f';

    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [BOT_CHANNEL_KEY]
    });

    const packet = MeshCorePacketDecoder.decode(hexData, { keyStore });

    expect(packet.isValid).toBe(true);
    expect(packet.routeType).toBe(RouteType.Flood);
    expect(packet.payloadType).toBe(PayloadType.GroupText);

    // Path encoding: 0x40 = hash_size=2, hop_count=0 (only set when > 1)
    expect(packet.pathHashSize).toBe(2);
    expect(packet.pathLength).toBe(0);
    expect(packet.path).toBeNull();

    // Should decrypt with #bot key
    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    expect(groupText.decrypted).toBeDefined();
    expect(groupText.decrypted?.sender).toBe('Howl 👾');
    expect(groupText.decrypted?.message).toBe('prefix 0101');
  });

  it('should decode single-byte hops (path_len = 0x00) for regression', () => {
    const hexData = '150013752F15A1BF3C018EB1FC4F26B5FAEB417BB0F1AE8FF07655484EBAA05CB9A927D689';

    const packet = MeshCorePacketDecoder.decode(hexData);

    expect(packet.isValid).toBe(true);
    expect(packet.routeType).toBe(RouteType.Flood);
    expect(packet.payloadType).toBe(PayloadType.GroupText);

    // Path encoding: 0x00 = hash_size=1, hop_count=0
    expect(packet.pathHashSize).toBe(1);
    expect(packet.pathLength).toBe(0);
    expect(packet.path).toBeNull();

    // Payload should parse correctly
    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    expect(groupText.channelHash).toBe('13');
  });

  it('should analyze structure of multi-byte hop packet', () => {
    const hexData = '15833fa002860ccae0eed9ca78b9ab0775d477c1f6490a398bf4edc75240';
    const structure = MeshCorePacketDecoder.analyzeStructure(hexData);

    // Path Length segment should have bit-level breakdown
    const pathLenSegment = structure.segments.find(s => s.name === 'Path Length');
    expect(pathLenSegment).toBeDefined();
    expect(pathLenSegment!.value).toBe('0x83');
    expect(pathLenSegment!.headerBreakdown).toBeDefined();
    expect(pathLenSegment!.headerBreakdown!.fields).toHaveLength(2);
    expect(pathLenSegment!.headerBreakdown!.fields[0].field).toBe('Hash Size');
    expect(pathLenSegment!.headerBreakdown!.fields[0].value).toBe('3 bytes per hop');
    expect(pathLenSegment!.headerBreakdown!.fields[1].field).toBe('Hop Count');
    expect(pathLenSegment!.headerBreakdown!.fields[1].value).toBe('3 hops');

    // Path Data segment should show grouped hashes
    const pathDataSegment = structure.segments.find(s => s.name === 'Path Data');
    expect(pathDataSegment).toBeDefined();
    expect(pathDataSegment!.value).toBe('3FA002860CCAE0EED9');
    expect(pathDataSegment!.description).toContain('3-byte hashes');
    expect(pathDataSegment!.description).toContain('Historical route taken');

    // Byte ranges should be contiguous
    let expectedByte = 0;
    for (const segment of structure.segments) {
      expect(segment.startByte).toBe(expectedByte);
      expectedByte = segment.endByte + 1;
    }
  });

  it('should reject reserved hash size (bits 7:6 = 11)', () => {
    // path_len = 0xC1 = bits 7:6 = 11 (reserved), hop_count = 1
    const hexData = '15C1FF00';
    const packet = MeshCorePacketDecoder.decode(hexData);
    expect(packet.isValid).toBe(false);
    expect(packet.errors).toBeDefined();
    expect(packet.errors![0]).toContain('reserved hash size');
  });
});

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

  it('should auto-detect 2-byte GroupText channel hash format', () => {
    // Same ciphertext as public channel sample, but with a 2-byte channel hash prefix (11E7)
    const hexData = '150011E7C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';

    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [
        '8b3387e9c5cdea6ac9e5edbaa115cd72'
      ]
    });

    const packet = MeshCorePacketDecoder.decode(hexData, {
      keyStore,
      groupTextChannelHashBytes: 'auto'
    });

    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    expect(groupText.channelHash).toBe('11E7');
    expect(groupText.cipherMac).toBe('C3C1');
    expect(groupText.decrypted).toBeDefined();
    expect(groupText.decrypted?.sender).toBe('🌲 Tree');
    expect(groupText.decrypted?.message).toBe('☁️');
  });

  it('should decrypt 2-byte GroupText channel hash when mode is forced', () => {
    const hexData = '150011E7C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D';

    const keyStore = MeshCorePacketDecoder.createKeyStore({
      channelSecrets: [
        '8b3387e9c5cdea6ac9e5edbaa115cd72'
      ]
    });

    const packet = MeshCorePacketDecoder.decode(hexData, {
      keyStore,
      groupTextChannelHashBytes: 2
    });

    const groupText = packet.payload.decoded as GroupTextPayload;
    expect(groupText.isValid).toBe(true);
    expect(groupText.channelHash).toBe('11E7');
    expect(groupText.decrypted).toBeDefined();
  });
});
