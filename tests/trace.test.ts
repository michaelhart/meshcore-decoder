import { MeshCorePacketDecoder, RouteType, PayloadType, PayloadVersion, TracePayload } from '../src';

describe('Trace Packets', () => {
  it('should decode trace packet', () => {
    const hexData = '260130A24D89BD0000000000FB';
    
    const packet = MeshCorePacketDecoder.decode(hexData);
    
    // Basic packet structure
    expect(packet.isValid).toBe(true);
    expect(packet.routeType).toBe(RouteType.Direct);
    expect(packet.payloadType).toBe(PayloadType.Trace);
    expect(packet.payloadVersion).toBe(PayloadVersion.Version1);
    
    // Payload should be decoded
    expect(packet.payload.decoded).toBeDefined();
    expect(packet.payload.decoded?.type).toBe(PayloadType.Trace);
    
    const trace = packet.payload.decoded as TracePayload;
    expect(trace.isValid).toBe(true);
    
    // Validate trace payload fields with hex breakdown
    expect(trace.traceTag).toBe('BD894DA2'); // Bytes 0-3: 0xA24D89BD
    expect(trace.authCode).toBe(0); // Bytes 4-7: 0x00000000
    expect(trace.flags).toBe(0); // Byte 8: 0x00
    expect(trace.pathHashes).toEqual(['FB']); // Byte 9: 0xFB (single path hash from payload)
    
    // Validate SNR calculation from path data (0x30 = 48, signed = 48, /4 = 12dB)
    expect(trace.snrValues).toEqual([12]);
    
    expect(packet.pathLength).toBe(1);
    expect(packet.path).toEqual(['30']);
    expect(packet.totalBytes).toBe(hexData.length / 2);
  });

  it('should handle invalid trace packets gracefully', () => {
    // Use a valid hex string but too short to be a valid packet
    const invalidHex = '26';
    const packet = MeshCorePacketDecoder.decode(invalidHex);
    expect(packet.isValid).toBe(false);
    expect(packet.errors).toBeDefined();
  });

  it('should handle short trace payloads', () => {
    const shortHex = '260100'; // Too short for trace payload
    const packet = MeshCorePacketDecoder.decode(shortHex);
    expect(packet.isValid).toBe(true); // Packet structure is valid
    
    if (packet.payload.decoded) {
      const trace = packet.payload.decoded as TracePayload;
      expect(trace.isValid).toBe(false);
      expect(trace.errors).toBeDefined();
    }
  });
});
