# MeshCore Packet Decoder Library - Comprehensive Plan

## Overview

This document outlines the plan for creating a standalone, public TypeScript library for decoding MeshCore packets. The library will consolidate all packet decoding logic currently scattered across the ingestor and analyzer codebases into a clean, focused, well-tested package that aligns with MeshCore's official documentation.

## Current State Analysis

### Existing Decoding Implementations

1. **Ingestor (`packet-decoder.ts`)**:
   - Main packet decoding logic with `PacketDecoder.decodeRawPacket()`
   - Handles Advert, Trace, GroupText, Request, AnonRequest, TextMessage payloads
   - Returns structured `DecodedPacketData` interface
   - Used by both `ingestor.ts` and `redecode.ts`

2. **Analyzer (`realtime-broker.ts`)**:
   - Detailed packet structure analysis with `decodePacketStructure()`
   - Provides byte-by-byte breakdown with segments
   - Handles all payload types with visual analysis
   - Returns detailed structure information for UI display

3. **RPC Methods (`rpc-methods.ts`)**:
   - Database queries and caching for decoded packets (completely irrelevant)
   - No direct decoding logic, but consumes decoded data

### Key Observations

- **Duplication**: Two separate decoding implementations with different purposes
- **Inconsistency**: Different interfaces and return types
- **Scattered Logic**: Payload-specific decoding spread across multiple methods
- **Documentation Alignment**: Some inconsistencies with official MeshCore docs

## New Library Architecture

### Core Design Principles

1. **Single Source of Truth**: One authoritative decoding implementation
2. **Documentation Alignment**: Strict adherence to `packet_structure.md` and `payloads.md`
3. **TypeScript First**: Full TypeScript with proper types, no compilation step for dev
4. **Modular Design**: Separate concerns for different use cases
5. **Comprehensive Testing**: Unit tests for all packet types and edge cases
6. **Clean API**: Simple, intuitive interfaces for different use cases

### Library Structure

```
meshcore-decoder/
├── src/
│   ├── index.ts                 # Main exports
│   ├── types/
│   │   ├── packet.ts           # Core packet interfaces
│   │   ├── payloads.ts         # Payload-specific interfaces
│   │   ├── enums.ts            # MeshCore constants and enums
│   │   └── crypto.ts           # Cryptographic interfaces
│   ├── decoder/
│   │   ├── packet-decoder.ts   # Main decoder class
│   │   ├── header-decoder.ts   # Header parsing logic
│   │   └── payload-decoders/
│   │       ├── advert.ts       # Advertisement payload decoder
│   │       ├── trace.ts        # Trace payload decoder
│   │       ├── group-text.ts   # Group text payload decoder
│   │       ├── request.ts      # Request payload decoder
│   │       ├── response.ts     # Response payload decoder
│   │       ├── text-message.ts # Text message payload decoder
│   │       ├── anon-request.ts # Anonymous request payload decoder
│   │       ├── ack.ts          # Acknowledgment payload decoder
│   │       └── index.ts        # Payload decoder registry
│   ├── analyzer/
│   │   ├── structure-analyzer.ts # Detailed packet structure analysis
│   │   └── segment-builder.ts    # UI segment building for visualization
│   ├── crypto/
│   │   ├── channel-crypto.ts   # Channel message decryption
│   │   ├── text-crypto.ts      # Text message decryption
│   │   ├── key-manager.ts      # Cryptographic key management
│   │   └── algorithms.ts       # Core crypto algorithms (AES, HMAC)
│   └── utils/
│       ├── crypto.ts           # Hash calculation utilities
│       ├── validation.ts       # Input validation
│       └── constants.ts        # MeshCore constants
├── tests/
│   ├── packets/               # Test packet samples
│   │   ├── advert-samples.ts  # Advertisement packet samples
│   │   ├── trace-samples.ts   # Trace packet samples
│   │   └── ...
│   ├── decoder.test.ts        # Main decoder tests
│   ├── payloads.test.ts       # Payload-specific tests
│   └── analyzer.test.ts       # Structure analyzer tests
├── package.json
├── tsconfig.json
├── README.md
└── CHANGELOG.md
```

## Core Interfaces

### Main Decoder Interface

```typescript
// Primary interface for basic packet decoding
interface DecodedPacket {
  // Packet metadata
  hash: string;
  messageHash: string;
  
  // Header information
  routeType: RouteType;
  payloadType: PayloadType;
  payloadVersion: PayloadVersion;
  
  // Transport and routing
  transportCodes?: [number, number];
  pathLength: number;
  path: string[] | null;
  
  // Payload data
  payload: {
    raw: string; // hex string
    decoded: PayloadData | null;
  };
  
  // Metadata
  totalBytes: number;
  isValid: boolean;
  errors?: string[];
}

// Interface for detailed structure analysis
interface PacketStructure {
  segments: PacketSegment[];
  totalBytes: number;
  rawHex: string;
  messageHash: string;
  payload: {
    segments: PayloadSegment[];
    hex: string;
    startByte: number;
    type: string;
  };
}

interface PacketSegment {
  name: string;
  description: string;
  startByte: number;
  endByte: number;
  value: string;
  headerBreakdown?: HeaderBreakdown;
}
```

### Payload Interfaces

```typescript
// Base payload interface
interface BasePayload {
  type: PayloadType;
  version: PayloadVersion;
  isValid: boolean;
  errors?: string[];
}

// Advertisement payload
interface AdvertPayload extends BasePayload {
  publicKey: string;
  timestamp: number;
  signature: string;
  appData: {
    flags: AdvertFlags;
    deviceRole: DeviceRole;
    hasLocation: boolean;
    hasName: boolean;
    location?: {
      latitude: number;
      longitude: number;
    };
    name?: string;
  };
}

// Trace payload
interface TracePayload extends BasePayload {
  traceTag: number;
  authCode: number;
  flags: number;
  pathHashes: string[];
  snrValues?: number[]; // From path field for TRACE packets
}

// Group text payload
interface GroupTextPayload extends BasePayload {
  channelHash: string;
  cipherMac: string;
  ciphertext: string; // Raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    flags: number;
    sender?: string;
    message: string;
  };
}

// Request payload
interface RequestPayload extends BasePayload {
  timestamp: number;
  requestType: RequestType;
  requestData?: string;
}

// Text message payload
interface TextMessagePayload extends BasePayload {
  destinationHash: string;
  sourceHash: string;
  cipherMac: string;
  ciphertext: string; // Raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    flags: number;
    attempt: number;
    message: string;
  };
}

// Anonymous request payload
interface AnonRequestPayload extends BasePayload {
  destinationHash: string;
  senderPublicKey: string;
  cipherMac: string;
  ciphertext: string; // Raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    syncTimestamp?: number; // Room server only
    password: string;
  };
}
```

### Cryptographic Interfaces

```typescript
// Key management for decryption
interface CryptoKeyStore {
  // Channel keys for GroupText decryption
  channelKeys: Map<string, string>; // channelHash -> key (hex)
  
  // Node keys for TextMessage/Request decryption
  nodeKeys: Map<string, string>; // nodePublicKey -> privateKey (hex)
  
  // Add/update keys
  addChannelKey(channelHash: string, key: string): void;
  addNodeKey(publicKey: string, privateKey: string): void;
  
  // Check if keys are available
  hasChannelKey(channelHash: string): boolean;
  hasNodeKey(publicKey: string): boolean;
}

// Decryption options
interface DecryptionOptions {
  keyStore?: CryptoKeyStore;
  attemptDecryption?: boolean; // Default: true if keyStore provided
  includeRawCiphertext?: boolean; // Default: true
}

// Decryption result
interface DecryptionResult {
  success: boolean;
  data?: any;
  error?: string;
}
```

### Enums (Aligned with MeshCore)

```typescript
export enum RouteType {
  TransportFlood = 0x00,
  Flood = 0x01,
  Direct = 0x02,
  TransportDirect = 0x03
}

export enum PayloadType {
  Request = 0x00,
  Response = 0x01,
  TextMessage = 0x02,
  Ack = 0x03,
  Advert = 0x04,
  GroupText = 0x05,
  GroupData = 0x06,
  AnonRequest = 0x07,
  Path = 0x08,
  Trace = 0x09,
  Multipart = 0x0A,
  RawCustom = 0x0F
}

export enum PayloadVersion {
  Version1 = 0x00,
  Version2 = 0x01,
  Version3 = 0x02,
  Version4 = 0x03
}

export enum DeviceRole {
  ChatNode = 0x01,
  Repeater = 0x02,
  RoomServer = 0x03,
  Sensor = 0x04
}

export enum AdvertFlags {
  HasLocation = 0x10,
  HasFeature1 = 0x20,
  HasFeature2 = 0x40,
  HasName = 0x80
}

export enum RequestType {
  GetStats = 0x01,
  Keepalive = 0x02, // deprecated
  GetTelemetryData = 0x03,
  GetMinMaxAvgData = 0x04,
  GetAccessList = 0x05
}
```

## Main API Design

### Primary Decoder Class

```typescript
export class MeshCorePacketDecoder {
  /**
   * Decode a raw packet from hex string
   * @param hexData Raw packet data as hex string
   * @param options Optional decryption options
   * @returns Decoded packet information
   */
  static decode(hexData: string, options?: DecryptionOptions): DecodedPacket {
    // Main decoding logic with optional decryption
  }
  
  /**
   * Analyze packet structure for detailed visualization
   * @param hexData Raw packet data as hex string
   * @param options Optional decryption options
   * @returns Detailed packet structure with segments
   */
  static analyze(hexData: string, options?: DecryptionOptions): PacketStructure {
    // Detailed structure analysis with decryption
  }
  
  /**
   * Validate packet format without full decoding
   * @param hexData Raw packet data as hex string
   * @returns Validation result
   */
  static validate(hexData: string): ValidationResult {
    // Quick validation
  }
  
  /**
   * Calculate message hash for a packet
   * @param hexData Raw packet data as hex string
   * @returns Message hash as hex string
   */
  static calculateHash(hexData: string): string {
    // Hash calculation
  }
  
  /**
   * Create a key store for decryption
   * @param initialKeys Optional initial keys
   * @returns New key store instance
   */
  static createKeyStore(initialKeys?: {
    channelKeys?: Record<string, string>;
    nodeKeys?: Record<string, string>;
  }): CryptoKeyStore {
    // Key store factory
  }
  
  /**
   * Decrypt a specific payload if keys are available
   * @param payload Encrypted payload
   * @param keyStore Key store containing decryption keys
   * @returns Decryption result
   */
  static decryptPayload(payload: any, keyStore: CryptoKeyStore): DecryptionResult {
    // Standalone payload decryption
  }
}
```

### Usage Examples

```typescript
import { MeshCorePacketDecoder, PayloadType } from 'meshcore-decoder';

// Basic decoding without decryption
const packet = MeshCorePacketDecoder.decode('11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172');

console.log(`Route Type: ${packet.routeType}`);
console.log(`Payload Type: ${packet.payloadType}`);
console.log(`Message Hash: ${packet.messageHash}`);

if (packet.payloadType === PayloadType.Advert && packet.payload.decoded) {
  const advert = packet.payload.decoded as AdvertPayload;
  console.log(`Device Name: ${advert.appData.name}`);
  console.log(`Device Role: ${advert.appData.deviceRole}`);
  if (advert.appData.location) {
    console.log(`Location: ${advert.appData.location.latitude}, ${advert.appData.location.longitude}`);
  }
}

// Decoding with decryption support
const keyStore = MeshCorePacketDecoder.createKeyStore({
  channelKeys: {
    '11': '8b3387e9c5cdea6ac9e5edbaa115cd72', // Public channel
    'cd': '1321f3257ae4f7125204096e15b34c99', // Testing (Puget Mesh)
    'd5': 'b7649d4716d918026af4e0f4068f7a03', // Howl Bot
    'ce': 'cc81b4d26638e4511bbe34e98c7f8b89', // Pixels
  }
});

const encryptedPacket = MeshCorePacketDecoder.decode(groupTextHexData, { keyStore });

if (encryptedPacket.payloadType === PayloadType.GroupText && encryptedPacket.payload.decoded) {
  const groupText = encryptedPacket.payload.decoded as GroupTextPayload;
  console.log(`Channel: ${groupText.channelHash}`);
  
  if (groupText.decrypted) {
    console.log(`Sender: ${groupText.decrypted.sender}`);
    console.log(`Message: ${groupText.decrypted.message}`);
    console.log(`Timestamp: ${new Date(groupText.decrypted.timestamp * 1000).toISOString()}`);
  } else {
    console.log('Message encrypted (no key available)');
  }
}

// Detailed analysis with decryption for UI
const structure = MeshCorePacketDecoder.analyze(groupTextHexData, { keyStore });
structure.payload.segments.forEach(segment => {
  console.log(`${segment.name}: ${segment.description}`);
  if (segment.decryptedMessage) {
    console.log(`  Decrypted: "${segment.decryptedMessage}"`);
  }
});
```

## Implementation Details

### Header Decoding

```typescript
class HeaderDecoder {
  static decode(headerByte: number): HeaderInfo {
    return {
      routeType: headerByte & 0x03,
      payloadType: (headerByte >> 2) & 0x0F,
      payloadVersion: (headerByte >> 6) & 0x03,
      hasTransportCodes: (headerByte & 0x03) === RouteType.TransportFlood || 
                        (headerByte & 0x03) === RouteType.TransportDirect
    };
  }
}
```

### Payload Decoder Registry

```typescript
class PayloadDecoderRegistry {
  private static decoders = new Map<PayloadType, PayloadDecoder>();
  
  static register(type: PayloadType, decoder: PayloadDecoder) {
    this.decoders.set(type, decoder);
  }
  
  static decode(type: PayloadType, data: Uint8Array): PayloadData | null {
    const decoder = this.decoders.get(type);
    return decoder ? decoder.decode(data) : null;
  }
}
```

### Cryptographic Implementation

```typescript
// Channel message decryption (based on home.ts implementation)
class ChannelCrypto {
  /**
   * Decrypt GroupText message using MeshCore algorithm:
   * - HMAC-SHA256 verification with 2-byte MAC
   * - AES-128 ECB decryption
   */
  static decryptGroupTextMessage(
    ciphertext: string, 
    channelHash: string, 
    cipherMac: string, 
    channelKey: string
  ): DecryptionResult {
    try {
      // Convert hex strings to bytes
      const ciphertextBytes = this.hexToBytes(ciphertext);
      const macBytes = this.hexToBytes(cipherMac);
      const keyBytes = this.hexToBytes(channelKey.padEnd(64, '0')); // Pad to 32 bytes, then hex = 64 chars
      
      // Verify HMAC (first 2 bytes)
      const computedMac = this.hmacSha256(ciphertextBytes, keyBytes).slice(0, 2);
      if (!this.constantTimeEquals(macBytes, computedMac)) {
        return { success: false, error: 'MAC verification failed' };
      }
      
      // Decrypt using AES-128 ECB
      const key = keyBytes.slice(0, 16); // First 16 bytes for AES-128
      const decrypted = this.aes128EcbDecrypt(ciphertextBytes, key);
      
      // Parse decrypted content: timestamp(4) + flags(1) + message
      if (decrypted.length < 5) {
        return { success: false, error: 'Decrypted content too short' };
      }
      
      const timestamp = this.readUint32LE(decrypted, 0);
      const flags = decrypted[4];
      const messageBytes = decrypted.slice(5);
      const message = new TextDecoder('utf-8').decode(messageBytes);
      
      // Parse sender and message (format: "sender: message")
      const colonIndex = message.indexOf(': ');
      let sender: string | undefined;
      let content: string;
      
      if (colonIndex > 0 && colonIndex < 50) {
        const potentialSender = message.substring(0, colonIndex);
        if (!/[:\[\]]/.test(potentialSender)) {
          sender = potentialSender;
          content = message.substring(colonIndex + 2);
        } else {
          content = message;
        }
      } else {
        content = message;
      }
      
      return {
        success: true,
        data: {
          timestamp,
          flags,
          sender,
          message: content
        }
      };
    } catch (error) {
      return { success: false, error: error instanceof Error ? error.message : 'Decryption failed' };
    }
  }
  
  private static hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
  
  private static readUint32LE(buffer: Uint8Array, offset: number): number {
    return buffer[offset] | 
           (buffer[offset + 1] << 8) | 
           (buffer[offset + 2] << 16) | 
           (buffer[offset + 3] << 24);
  }
  
  // Crypto primitives would be implemented using Web Crypto API or Node.js crypto
  private static hmacSha256(data: Uint8Array, key: Uint8Array): Uint8Array {
    // Implementation using crypto.subtle.importKey + crypto.subtle.sign
  }
  
  private static aes128EcbDecrypt(data: Uint8Array, key: Uint8Array): Uint8Array {
    // Implementation using crypto.subtle.importKey + crypto.subtle.decrypt
  }
  
  private static constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }
}
```

### Sample Unit Test

```typescript
describe('MeshCorePacketDecoder', () => {
  describe('Advertisement Packets', () => {
    it('should decode Cougar repeater advertisement', () => {
      const hexData = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';
      
      const packet = MeshCorePacketDecoder.decode(hexData);
      
      expect(packet.isValid).toBe(true);
      expect(packet.routeType).toBe(RouteType.Flood);
      expect(packet.payloadType).toBe(PayloadType.Advert);
      expect(packet.payloadVersion).toBe(PayloadVersion.Version1);
      
      const advert = packet.payload.decoded as AdvertPayload;
      expect(advert.appData.deviceRole).toBe(DeviceRole.Repeater);
      expect(advert.appData.name).toBe('WW7STR/PugetMesh Cougar');
      expect(advert.appData.hasName).toBe(true);
      expect(advert.appData.hasLocation).toBe(false);
    });
  });
  
  describe('GroupText Decryption', () => {
    it('should decrypt public channel messages', () => {
      const keyStore = MeshCorePacketDecoder.createKeyStore({
        channelKeys: {
          '11': '8b3387e9c5cdea6ac9e5edbaa115cd72' // Public channel
        }
      });
      
      // Sample GroupText packet (would need real encrypted sample)
      const packet = MeshCorePacketDecoder.decode(groupTextHexData, { keyStore });
      
      expect(packet.payloadType).toBe(PayloadType.GroupText);
      const groupText = packet.payload.decoded as GroupTextPayload;
      expect(groupText.channelHash).toBe('11');
      expect(groupText.decrypted).toBeDefined();
      expect(groupText.decrypted?.message).toContain('test message');
    });
    
    it('should handle encrypted messages without keys', () => {
      const packet = MeshCorePacketDecoder.decode(groupTextHexData); // No keyStore
      
      const groupText = packet.payload.decoded as GroupTextPayload;
      expect(groupText.ciphertext).toBeDefined();
      expect(groupText.decrypted).toBeUndefined();
    });
  });
});
```

## Development Setup

### Package Configuration

```json
{
  "name": "meshcore-decoder",
  "version": "1.0.0",
  "description": "TypeScript library for decoding MeshCore mesh networking packets",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "dev": "ts-node src/index.ts",
    "test": "jest",
    "test:watch": "jest --watch",
    "build": "tsc",
    "build:watch": "tsc --watch",
    "lint": "eslint src/**/*.ts",
    "format": "prettier --write src/**/*.ts"
  },
  "keywords": ["meshcore", "mesh", "networking", "packet", "decoder", "radio"],
  "author": "MeshCore Team",
  "license": "MIT",
  "dependencies": {
    "crypto-js": "^4.2.0"
  },
  "devDependencies": {
    "@types/crypto-js": "^4.2.0",
    "@types/jest": "^29.5.0",
    "@types/node": "^20.0.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0",
    "jest": "^29.5.0",
    "prettier": "^3.0.0",
    "ts-jest": "^29.1.0",
    "ts-node": "^10.9.0",
    "typescript": "^5.0.0"
  }
}
```

### TypeScript Configuration

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

## Migration Strategy

### Phase 1: Library Development (Current Focus)
- Create new repository with clean implementation
- Implement core decoding logic aligned with MeshCore docs
- Add comprehensive unit tests
- Set up development tooling (ts-node, jest, etc.)
- Create initial unit test for Cougar advertisement packet

### Phase 2: Integration Planning
- Design adapter interfaces for existing codebases
- Plan migration path for ingestor
- Plan migration path for analyzer
- Identify breaking changes and compatibility issues

### Phase 3: Integration Implementation
- Replace ingestor packet-decoder.ts with new library
- Replace analyzer decoding logic with new library
- Update database schemas if needed
- Comprehensive testing in production environment

## Key Differences from Current Implementation

### Improvements
1. **Unified API**: Single library serving both basic decoding and detailed analysis
2. **Better Type Safety**: Comprehensive TypeScript interfaces
3. **Documentation Alignment**: Strict adherence to official MeshCore documentation
4. **Modular Design**: Separate payload decoders for maintainability
5. **Comprehensive Testing**: Unit tests for all packet types and edge cases
6. **Clean Architecture**: Separation of concerns between decoding and analysis
7. **Complete Decryption Support**: Built-in decryption for encrypted payloads with configurable keys

### Compatibility Considerations
1. **Interface Changes**: New interfaces may require adapter layers
2. **Error Handling**: Improved error handling may change behavior
3. **Performance**: New implementation may have different performance characteristics
4. **Dependencies**: Minimal dependencies to reduce maintenance burden

## Success Criteria

1. **Functional**: Successfully decode all existing packet types with structural analysis
2. **Complete Decryption**: Support decryption of all encrypted payload types (GroupText, TextMessage, AnonRequest, Response)
3. **Compatible**: Drop-in replacement for existing decoders (with adapters) 
4. **Tested**: 100% test coverage for core decoding and decryption logic
5. **Documented**: Comprehensive API documentation and examples including decryption usage
6. **Maintainable**: Clean, modular code that's easy to extend
7. **Performant**: No significant performance regression
8. **Secure**: Proper cryptographic implementations with constant-time comparisons

## Next Steps

1. **Create Repository**: Set up new repository with initial structure
2. **Implement Core**: Start with basic packet structure decoding
3. **Add Advertisement Decoder**: Implement advertisement payload decoder
4. **Create Unit Test**: Add test for Cougar advertisement packet
5. **Iterate**: Expand to other payload types based on feedback

This plan provides a comprehensive roadmap for creating a standalone, production-ready MeshCore packet decoder library that consolidates existing functionality while improving maintainability, testability, and alignment with official documentation.
