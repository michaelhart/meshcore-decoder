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
    expect(trace.traceTag).toBe('BD894DA2');
    expect(trace.authCode).toBe(0);
    expect(trace.flags).toBe(0);
    expect(trace.pathHashes).toEqual(['fb']);
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
