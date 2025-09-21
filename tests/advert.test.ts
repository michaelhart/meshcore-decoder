import { MeshCorePacketDecoder, RouteType, PayloadType, PayloadVersion, DeviceRole, AdvertPayload } from '../src';

describe('MeshCorePacketDecoder', () => {
  describe('Advertisement Packets', () => {
    it('should decode Cougar repeater advertisement', () => {
      const hexData = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      // Basic packet structure
      expect(packet.isValid).toBe(true);
      expect(packet.routeType).toBe(RouteType.Flood);
      expect(packet.payloadType).toBe(PayloadType.Advert);
      expect(packet.payloadVersion).toBe(PayloadVersion.Version1);
      
      // Payload should be decoded
      expect(packet.payload.decoded).toBeDefined();
      expect(packet.payload.decoded?.type).toBe(PayloadType.Advert);
      
      const advert = packet.payload.decoded as AdvertPayload;
      expect(advert.isValid).toBe(true);
      expect(advert.appData.deviceRole).toBe(DeviceRole.Repeater);
      expect(advert.appData.name).toBe('WW7STR/PugetMesh Cougar');
      expect(advert.appData.hasName).toBe(true);
      expect(advert.appData.hasLocation).toBe(true);
      expect(advert.appData.location?.latitude).toBeCloseTo(47.543968, 6);
      expect(advert.appData.location?.longitude).toBeCloseTo(-122.108616, 6);
      
      // Verify packet structure
      expect(packet.pathLength).toBe(0); // No path for this packet
      expect(packet.path).toBeNull();
      expect(packet.totalBytes).toBe(hexData.length / 2); // Hex string length / 2
    });

    it('should handle invalid packets gracefully', () => {
      const packet = MeshCorePacketDecoder.decode('11'); // Too short
      
      expect(packet.isValid).toBe(false);
      expect(packet.errors).toContain('Packet too short (minimum 2 bytes required)');
    });

    it('should validate packet structure', () => {
      const hexData = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';
      
      const validation = MeshCorePacketDecoder.validate(hexData);
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toBeUndefined();
    });

    it('should create key store', () => {
      const keyStore = MeshCorePacketDecoder.createKeyStore({
        channelSecrets: [
          '8b3387e9c5cdea6ac9e5edbaa115cd72'
        ]
      });
      
      expect(keyStore.hasChannelKey('11')).toBe(true); // '11' is the hash of the public key
      expect(keyStore.hasChannelKey('22')).toBe(false);
    });
  });
});
