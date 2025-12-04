import { 
  MeshCorePacketDecoder, 
  RouteType, 
  PayloadType, 
  PayloadVersion,
  ControlSubType,
  DeviceRole,
  ControlDiscoverReqPayload,
  ControlDiscoverRespPayload
} from '../src';

describe('Control Packets', () => {
  describe('DISCOVER_RESP packets', () => {
    // Real packet from API: DISCOVER_RESP from a Repeater node
    // Raw: 2E0092DC35333E5B4FBB374D26E77A3AF0A0E3D34A7174131BBEBF2341EE948B6F4B13CF800C928F
    // Header: 0x2E = Route Direct (0x02), PayloadType Control (0x0B), Version 1
    // Path Length: 0x00 (no path)
    // Payload:
    //   0x92 = subtype DISCOVER_RESP (0x9), node_type Repeater (0x2)
    //   0xDC = SNR byte
    //   35333E5B = tag (little endian)
    //   4FBB374D26E77A3AF0A0E3D34A7174131BBEBF2341EE948B6F4B13CF800C928F = 32-byte pubkey
    it('should decode DISCOVER_RESP packet from Repeater', () => {
      const hexData = '2E0092DC35333E5B4FBB374D26E77A3AF0A0E3D34A7174131BBEBF2341EE948B6F4B13CF800C928F';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      // Basic packet structure
      expect(packet.isValid).toBe(true);
      expect(packet.routeType).toBe(RouteType.Direct);
      expect(packet.payloadType).toBe(PayloadType.Control);
      expect(packet.payloadVersion).toBe(PayloadVersion.Version1);
      expect(packet.pathLength).toBe(0);
      expect(packet.path).toBeNull();
      
      // Payload should be decoded
      expect(packet.payload.decoded).toBeDefined();
      expect(packet.payload.decoded?.type).toBe(PayloadType.Control);
      
      const control = packet.payload.decoded as ControlDiscoverRespPayload;
      expect(control.isValid).toBe(true);
      expect(control.subType).toBe(ControlSubType.NodeDiscoverResp);
      
      // Validate DISCOVER_RESP specific fields
      expect(control.nodeType).toBe(DeviceRole.Repeater);
      expect(control.nodeTypeName).toBe('Repeater');
      
      // SNR: 0xDC = 220 unsigned, -36 signed, /4 = -9 dB
      expect(control.snr).toBe(-9);
      
      // Tag: 35333E5B (little endian) = 0x5B3E3335
      expect(control.tag).toBe(0x5B3E3335);
      
      // Public key: 32 bytes
      expect(control.publicKeyLength).toBe(32);
      expect(control.publicKey).toBe('4FBB374D26E77A3AF0A0E3D34A7174131BBEBF2341EE948B6F4B13CF800C928F');
    });

    it('should decode DISCOVER_RESP with short prefix-only pubkey', () => {
      // Construct a packet with 8-byte pubkey prefix
      // Header: 0x2E, Path: 0x00, Payload: 0x92 + SNR + 4-byte tag + 8-byte pubkey
      const hexData = '2E00920435333E5B0102030405060708';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      expect(packet.isValid).toBe(true);
      expect(packet.payloadType).toBe(PayloadType.Control);
      
      const control = packet.payload.decoded as ControlDiscoverRespPayload;
      expect(control.isValid).toBe(true);
      expect(control.subType).toBe(ControlSubType.NodeDiscoverResp);
      expect(control.nodeType).toBe(DeviceRole.Repeater);
      
      // SNR: 0x04 = 4, /4 = 1 dB
      expect(control.snr).toBe(1);
      
      // Public key prefix: 8 bytes
      expect(control.publicKeyLength).toBe(8);
      expect(control.publicKey).toBe('0102030405060708');
    });

    it('should decode DISCOVER_RESP from different node types', () => {
      // Chat node (0x91)
      const chatPacket = MeshCorePacketDecoder.decode('2E009108AABBCCDD0102030405060708');
      const chatControl = chatPacket.payload.decoded as ControlDiscoverRespPayload;
      expect(chatControl.nodeType).toBe(DeviceRole.ChatNode);
      expect(chatControl.nodeTypeName).toBe('Chat Node');
      
      // Room server (0x93)
      const roomPacket = MeshCorePacketDecoder.decode('2E009308AABBCCDD0102030405060708');
      const roomControl = roomPacket.payload.decoded as ControlDiscoverRespPayload;
      expect(roomControl.nodeType).toBe(DeviceRole.RoomServer);
      expect(roomControl.nodeTypeName).toBe('Room Server');
      
      // Sensor (0x94)
      const sensorPacket = MeshCorePacketDecoder.decode('2E009408AABBCCDD0102030405060708');
      const sensorControl = sensorPacket.payload.decoded as ControlDiscoverRespPayload;
      expect(sensorControl.nodeType).toBe(DeviceRole.Sensor);
      expect(sensorControl.nodeTypeName).toBe('Sensor');
    });

    it('should handle negative SNR values correctly', () => {
      // SNR 0xDC = 220 unsigned = -36 signed, /4 = -9 dB
      const packet1 = MeshCorePacketDecoder.decode('2E0092DC35333E5B0102030405060708');
      const control1 = packet1.payload.decoded as ControlDiscoverRespPayload;
      expect(control1.snr).toBe(-9);
      
      // SNR 0x80 = 128 unsigned = -128 signed, /4 = -32 dB
      const packet2 = MeshCorePacketDecoder.decode('2E00928035333E5B0102030405060708');
      const control2 = packet2.payload.decoded as ControlDiscoverRespPayload;
      expect(control2.snr).toBe(-32);
      
      // SNR 0x7F = 127, /4 = 31.75 dB
      const packet3 = MeshCorePacketDecoder.decode('2E00927F35333E5B0102030405060708');
      const control3 = packet3.payload.decoded as ControlDiscoverRespPayload;
      expect(control3.snr).toBe(31.75);
    });
  });

  describe('DISCOVER_REQ packets', () => {
    it('should decode DISCOVER_REQ packet', () => {
      // Construct a DISCOVER_REQ packet
      // Header: 0x2E (Direct, Control, V1), Path: 0x00
      // Payload: 0x80 (DISCOVER_REQ, prefix_only=0) + filter + tag
      const hexData = '2E0080040102030400000000'; // filter=0x04 (Repeater), tag=0x03020104, since=0
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      expect(packet.isValid).toBe(true);
      expect(packet.payloadType).toBe(PayloadType.Control);
      
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      expect(control.isValid).toBe(true);
      expect(control.subType).toBe(ControlSubType.NodeDiscoverReq);
      expect(control.prefixOnly).toBe(false);
      expect(control.typeFilter).toBe(0x04); // Bit 2 = Repeater
      expect(control.typeFilterNames).toContain('Repeater');
      expect(control.tag).toBe(0x04030201);
      expect(control.since).toBe(0);
    });

    it('should decode DISCOVER_REQ with prefix_only flag', () => {
      // 0x81 = DISCOVER_REQ with prefix_only=1
      const hexData = '2E00810401020304';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      
      expect(control.prefixOnly).toBe(true);
    });

    it('should decode DISCOVER_REQ with since timestamp', () => {
      // With since timestamp (10 bytes total payload)
      const hexData = '2E00800401020304DCBA9876'; // since=0x7698BADC
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      
      expect(control.isValid).toBe(true);
      expect(control.tag).toBe(0x04030201);
      expect(control.since).toBe(0x7698BADC);
    });

    it('should decode type filter correctly', () => {
      // Filter for Chat (bit 1) + Repeater (bit 2) = 0x06
      const hexData = '2E00800601020304';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      
      expect(control.typeFilter).toBe(0x06);
      expect(control.typeFilterNames).toContain('Chat');
      expect(control.typeFilterNames).toContain('Repeater');
      expect(control.typeFilterNames).not.toContain('Room');
      expect(control.typeFilterNames).not.toContain('Sensor');
    });

    it('should handle all node types in filter', () => {
      // Filter for all types (bits 1-4) = 0x1E
      const hexData = '2E00801E01020304';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      
      expect(control.typeFilterNames).toContain('Chat');
      expect(control.typeFilterNames).toContain('Repeater');
      expect(control.typeFilterNames).toContain('Room');
      expect(control.typeFilterNames).toContain('Sensor');
    });
  });

  describe('Error handling', () => {
    it('should handle payload too short for DISCOVER_RESP', () => {
      // Only 13 bytes in payload (needs at least 14)
      const hexData = '2E00920401020304010203040506';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverRespPayload;
      
      expect(control.isValid).toBe(false);
      expect(control.errors).toBeDefined();
    });

    it('should handle payload too short for DISCOVER_REQ', () => {
      // Only 5 bytes in payload (needs at least 6)
      const hexData = '2E00800401020304'.slice(0, 14); // Truncate to only 5 payload bytes
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      
      expect(control.isValid).toBe(false);
      expect(control.errors).toBeDefined();
    });

    it('should handle unknown control sub-type', () => {
      // 0xA0 is not a known sub-type
      const hexData = '2E00A00401020304';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      const control = packet.payload.decoded;
      
      expect(control?.isValid).toBe(false);
      expect(control?.errors?.[0]).toContain('Unknown control sub-type');
    });
  });

  describe('Structure analysis', () => {
    it('should generate segments for DISCOVER_RESP', () => {
      const hexData = '2E0092DC35333E5B0102030405060708';
      
      const structure = MeshCorePacketDecoder.analyzeStructure(hexData);
      
      expect(structure.payload.segments.length).toBeGreaterThan(0);
      
      // Check for expected segment names
      const segmentNames = structure.payload.segments.map(s => s.name);
      expect(segmentNames).toContain('Flags');
      expect(segmentNames).toContain('SNR');
      expect(segmentNames).toContain('Tag');
      expect(segmentNames.some(n => n.includes('Public Key'))).toBe(true);
    });

    it('should generate segments for DISCOVER_REQ', () => {
      const hexData = '2E00800401020304';
      
      const structure = MeshCorePacketDecoder.analyzeStructure(hexData);
      
      const segmentNames = structure.payload.segments.map(s => s.name);
      expect(segmentNames).toContain('Flags');
      expect(segmentNames).toContain('Type Filter');
      expect(segmentNames).toContain('Tag');
    });
  });

  describe('Real API packets', () => {
    // These are real packets from the API
    const realPackets = [
      // From Z_Observer - BIC
      '2E009209B32601F558EE6D48FED50AC95FDDD9C38C9F80156F1F6C5D5A075E0A3912FECC1E47D8F8',
      '2E00922CB32601F57A2859FF1D754965F798452A6857059A1EFF151C798A1B9CC05169BC8247EAD5',
      '2E0092DEB32601F5CF43AF0CEC2976CD39C2DCE8BDA4CB0399936B4BD2D2867C4CC82CDD474EE454',
      // From Moscow observers
      '2E0092DC35333E5B4FBB374D26E77A3AF0A0E3D34A7174131BBEBF2341EE948B6F4B13CF800C928F',
      '2E00921035333E5BD44DE9DD6E165ACA8C71717DFE7418E74E999A0EABFBAF36CF2D53B1D46A7268',
    ];

    it.each(realPackets)('should decode real DISCOVER_RESP packet: %s', (hexData) => {
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      expect(packet.isValid).toBe(true);
      expect(packet.payloadType).toBe(PayloadType.Control);
      
      const control = packet.payload.decoded as ControlDiscoverRespPayload;
      expect(control.isValid).toBe(true);
      expect(control.subType).toBe(ControlSubType.NodeDiscoverResp);
      expect(control.nodeType).toBe(DeviceRole.Repeater); // All these are from repeaters
      expect(control.publicKeyLength).toBe(32);
    });

    it('should decode short DISCOVER_RESP packet from API', () => {
      // This is a short packet with only 8 bytes payload (prefix pubkey)
      const hexData = '2E008004518B748F';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      expect(packet.isValid).toBe(true);
      expect(packet.payloadType).toBe(PayloadType.Control);
      
      // This packet has 0x80 as first byte which is DISCOVER_REQ not DISCOVER_RESP
      const control = packet.payload.decoded as ControlDiscoverReqPayload;
      expect(control.isValid).toBe(true);
      expect(control.subType).toBe(ControlSubType.NodeDiscoverReq);
    });
  });
});

