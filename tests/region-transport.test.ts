import {
  calcRegionKey,
  calcTransportCode,
  calcTransportCodeForRegion,
  transportCodeMatchesRegion,
  REGION_KEY_SIZE,
  MeshCorePacketDecoder,
  PayloadType
} from '../src';

describe('Region transport code', () => {
  it('calcRegionKey returns 16 bytes from region name', () => {
    const key = calcRegionKey('#Europe');
    expect(key.length).toBe(REGION_KEY_SIZE);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(calcRegionKey('#Europe')).toEqual(key);
    expect(calcRegionKey('Europe').length).toBe(16);
  });

  it('prepends # when missing (firmware implicit auto hashtag): ottawa and #ottawa same key', () => {
    expect(calcRegionKey('ottawa')).toEqual(calcRegionKey('#ottawa'));
    expect(calcRegionKey('Europe')).toEqual(calcRegionKey('#Europe'));
  });

  it('calcTransportCode returns value in valid range (0 and 0xFFFF reserved)', () => {
    const key = calcRegionKey('#Test');
    const payload = new Uint8Array([0x59, 0x6e, 0xa2, 0x36, 0x22]); // sample payload
    const code = calcTransportCode(key, PayloadType.GroupText, payload);
    expect(code).toBeGreaterThanOrEqual(1);
    expect(code).toBeLessThanOrEqual(0xfffe);
    expect(typeof code).toBe('number');
  });

  it('calcTransportCodeForRegion matches calcTransportCode with same key', () => {
    const name = '#MyRegion';
    const payload = new Uint8Array(10);
    const key = calcRegionKey(name);
    expect(calcTransportCodeForRegion(name, PayloadType.GroupText, payload)).toBe(
      calcTransportCode(key, PayloadType.GroupText, payload)
    );
  });

  it('transportCodeMatchesRegion is true when code matches computed code', () => {
    const payloadHex = '596EA23622BCB4D5945E49348165AF7DABA3F5DCEED85F430E0856DB5B591E86AB3363BC00E1BA30776698F72FC57C7168E66A4875CDB710F3C175FC2B3FE75A036EF14FA59A709062D3A9FF7014F2E7A8512C';
    const code = calcTransportCodeForRegion('#SomeRegion', PayloadType.GroupText, hexToBytes(payloadHex));
    expect(transportCodeMatchesRegion('#SomeRegion', PayloadType.GroupText, payloadHex, code)).toBe(true);
    expect(transportCodeMatchesRegion('#OtherRegion', PayloadType.GroupText, payloadHex, code)).toBe(false);
  });

  it('decoded TransportFlood packet: transport code can be checked against region', () => {
    const hex =
      '14FA1A0000034E927D596EA23622BCB4D5945E49348165AF7DABA3F5DCEED85F430E0856DB5B591E86AB3363BC00E1BA30776698F72FC57C7168E66A4875CDB710F3C175FC2B3FE75A036EF14FA59A709062D3A9FF7014F2E7A8512C';
    const packet = MeshCorePacketDecoder.decode(hex);
    expect(packet.isValid).toBe(true);
    expect(packet.transportCodes).toEqual([0x1afa, 0]); // 6906, 0

    const payloadRaw = packet.payload.raw;
    const computed = calcTransportCodeForRegion(
      '#UnknownRegionName',
      packet.payloadType,
      hexToBytes(payloadRaw)
    );
    expect(transportCodeMatchesRegion('#UnknownRegionName', packet.payloadType, payloadRaw, computed)).toBe(true);
    expect(transportCodeMatchesRegion('#UnknownRegionName', packet.payloadType, payloadRaw, packet.transportCodes![0])).toBe(
      computed === packet.transportCodes![0]
    );
  });

  it('ottawa without # matches packet region (#ottawa): transport code 0x1AFA', () => {
    const hex =
      '14FA1A0000034E927D596EA23622BCB4D5945E49348165AF7DABA3F5DCEED85F430E0856DB5B591E86AB3363BC00E1BA30776698F72FC57C7168E66A4875CDB710F3C175FC2B3FE75A036EF14FA59A709062D3A9FF7014F2E7A8512C';
    const packet = MeshCorePacketDecoder.decode(hex);
    const payloadRaw = packet.payload.raw;
    expect(transportCodeMatchesRegion('ottawa', packet.payloadType, payloadRaw, packet.transportCodes![0])).toBe(true);
    expect(transportCodeMatchesRegion('#ottawa', packet.payloadType, payloadRaw, packet.transportCodes![0])).toBe(true);
  });
});

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '').toUpperCase();
  const len = clean.length / 2;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
