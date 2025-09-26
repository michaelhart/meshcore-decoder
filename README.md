# MeshCore Decoder

A TypeScript library for decoding MeshCore mesh networking packets with full cryptographic support.

This powers the [MeshCore Packet Analyzer](https://analyzer.letsme.sh/).

## Features

- **Packet Decoding**: Decode MeshCore packets
- **Built-in Decryption**: Decrypt GroupText, TextMessage, and other encrypted payloads
- **Developer Friendly**: TypeScript-first with full type safety and portability of JavaScript

## Installation

### Install to a single project

```bash
npm install @michaelhart/meshcore-decoder
```

### Install CLI (install globally)

```bash
npm install -g @michaelhart/meshcore-decoder
```

## Quick Start

```typescript
import { 
  MeshCoreDecoder, 
  PayloadType,
  Utils,
  DecodedPacket,
  AdvertPayload 
} from '@michaelhart/meshcore-decoder';

// Decode a MeshCore packet
const hexData: string = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

const packet: DecodedPacket = MeshCoreDecoder.decode(hexData);

console.log(`Route Type: ${Utils.getRouteTypeName(packet.routeType)}`);
console.log(`Payload Type: ${Utils.getPayloadTypeName(packet.payloadType)}`);
console.log(`Message Hash: ${packet.messageHash}`);

if (packet.payloadType === PayloadType.Advert && packet.payload.decoded) {
  const advert: AdvertPayload = packet.payload.decoded as AdvertPayload;
  console.log(`Device Name: ${advert.appData.name}`);
  console.log(`Device Role: ${Utils.getDeviceRoleName(advert.appData.deviceRole)}`);
  if (advert.appData.location) {
    console.log(`Location: ${advert.appData.location.latitude}, ${advert.appData.location.longitude}`);
  }
}
```

## Full Packet Structure Example

Here's what a complete decoded packet looks like:

```typescript
import { MeshCoreDecoder, DecodedPacket } from '@michaelhart/meshcore-decoder';

const hexData: string = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

const packet: DecodedPacket = MeshCoreDecoder.decode(hexData);

console.log(JSON.stringify(packet, null, 2));
```

**Output:**
```json
{
  "messageHash": "F9C060FE",
  "routeType": 1,
  "payloadType": 4,
  "payloadVersion": 0,
  "pathLength": 0,
  "path": null,
  "payload": {
    "raw": "7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172",
    "decoded": {
      "type": 4,
      "version": 0,
      "isValid": true,
      "publicKey": "7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400",
      "timestamp": 1758455660,
      "signature": "2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609",
      "appData": {
        "flags": 146,
        "deviceRole": 2,
        "hasLocation": true,
        "hasName": true,
        "location": {
          "latitude": 47.543968,
          "longitude": -122.108616
        },
        "name": "WW7STR/PugetMesh Cougar"
      }
    }
  },
  "totalBytes": 134,
  "isValid": true
}
```

## Packet Support

| Value | Name | Description | Decoding | Decryption | Segment Analysis |
|-------|------|-------------|----------|------------|------------------|
| `0x00` | Request | Request (destination/source hashes + MAC) | ✅ | 🚧 | ✅ |
| `0x01` | Response | Response to REQ or ANON_REQ | ✅ | 🚧 | ✅ |
| `0x02` | Plain text message | Plain text message | ✅ | 🚧 | ✅ |
| `0x03` | Acknowledgment | Acknowledgment | ✅ | N/A | ✅ |
| `0x04` | Node advertisement | Node advertisement | ✅ | N/A | ✅ |
| `0x05` | Group text message | Group text message | ✅ | ✅ | ✅ |
| `0x06` | Group datagram | Group datagram | 🚧 | 🚧 | 🚧 |
| `0x07` | Anonymous request | Anonymous request | ✅ | 🚧 | ✅ |
| `0x08` | Returned path | Returned path | ✅ | N/A | ✅ |
| `0x09` | Trace | Trace a path, collecting SNI for each hop | ✅ | N/A | ✅ |
| `0x0A` | Multi-part packet | Packet is part of a sequence of packets | 🚧 | 🚧 | 🚧 |
| `0x0F` | Custom packet | Custom packet (raw bytes, custom encryption) | 🚧 | 🚧 | 🚧 |

**Legend:**
- ✅ Fully implemented
- 🚧 Planned/In development
- `-` Not applicable

For some packet types not yet supported here, they may not exist in MeshCore yet or I have yet to observe these packet types on the mesh.

## Decryption Support

Simply provide your channel secret keys and the library handles everything else:

```typescript
import { 
  MeshCoreDecoder, 
  PayloadType,
  CryptoKeyStore,
  DecodedPacket,
  GroupTextPayload 
} from '@michaelhart/meshcore-decoder';

// Create a key store with channel secret keys
const keyStore: CryptoKeyStore = MeshCoreDecoder.createKeyStore({
  channelSecrets: [
    '8b3387e9c5cdea6ac9e5edbaa115cd72', // Public channel (channel hash 11)
    'ff2b7d74e8d20f71505bda9ea8d59a1c', // A different channel's secret
  ]
});

const groupTextHexData: string = '...'; // Your encrypted GroupText packet hex

// Decode encrypted GroupText message
const encryptedPacket: DecodedPacket = MeshCoreDecoder.decode(groupTextHexData, { keyStore });

if (encryptedPacket.payloadType === PayloadType.GroupText && encryptedPacket.payload.decoded) {
  const groupText: GroupTextPayload = encryptedPacket.payload.decoded as GroupTextPayload;
  
  if (groupText.decrypted) {
    console.log(`Sender: ${groupText.decrypted.sender}`);
    console.log(`Message: ${groupText.decrypted.message}`);
    console.log(`Timestamp: ${new Date(groupText.decrypted.timestamp * 1000).toISOString()}`);
  } else {
    console.log('Message encrypted (no key available)');
  }
}
```

The library automatically:
- Calculates channel hashes from your secret keys using SHA256
- Handles hash collisions (multiple keys with same first byte) by trying all matching keys
- Verifies message authenticity using HMAC-SHA256
- Decrypts using AES-128 ECB

## Packet Structure Analysis

For detailed packet analysis and debugging, use `analyzeStructure()` to get byte-level breakdowns:

```typescript
import { MeshCoreDecoder, PacketStructure } from '@michaelhart/meshcore-decoder';

console.log('=== Packet Breakdown ===');
const hexData: string = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

console.log('Packet length:', hexData.length);
console.log('Expected bytes:', hexData.length / 2);

const structure: PacketStructure = MeshCoreDecoder.analyzeStructure(hexData);
console.log('\nMain segments:');
structure.segments.forEach((seg, i) => {
  console.log(`${i+1}. ${seg.name} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
});

console.log('\nPayload segments:');
structure.payload.segments.forEach((seg, i) => {
  console.log(`${i+1}. ${seg.name} (bytes ${seg.startByte}-${seg.endByte}): ${seg.value}`);
  console.log(`   Description: ${seg.description}`);
});
```

**Output:**
```
=== Packet Breakdown ===
Packet length: 268
Expected bytes: 134

Main segments:
1. Header (bytes 0-0): 0x11
2. Path Length (bytes 1-1): 0x00
3. Payload (bytes 2-133): 7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

Payload segments:
1. Public Key (bytes 0-31): 7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400
   Description: Ed25519 public key
2. Timestamp (bytes 32-35): 6CE7CF68
   Description: 1758455660 (2025-09-21T11:54:20Z)
3. Signature (bytes 36-99): 2E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E609
   Description: Ed25519 signature
4. App Flags (bytes 100-100): 92
   Description: Binary: 10010010 | Bits 0-3 (Role): Room server | Bit 4 (Location): Yes | Bit 5 (Feature1): No | Bit 6 (Feature2): No | Bit 7 (Name): Yes
5. Latitude (bytes 101-104): A076D502
   Description: 47.543968° (47.543968)
6. Longitude (bytes 105-108): 38C5B8F8
   Description: -122.108616° (-122.108616)
7. Node Name (bytes 109-131): 5757375354522F50756765744D65736820436F75676172
   Description: Node name: "WW7STR/PugetMesh Cougar"
```

The `analyzeStructure()` method provides:
- **Header breakdown** with bit-level field analysis
- **Byte-accurate segments** with start/end positions
- **Payload field parsing** for all supported packet types
- **Human-readable descriptions** for each field

### Command Line Interface

For quick analysis from the terminal, install globally and use the CLI:

```bash
# Install globally
npm install -g @michaelhart/meshcore-decoder

# Analyze a packet
meshcore-decoder 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

# With decryption (provide channel secrets)
meshcore-decoder 150011C3C1354D619BAE9590E4D177DB7EEAF982F5BDCF78005D75157D9535FA90178F785D --key 8b3387e9c5cdea6ac9e5edbaa115cd72

# Show detailed structure analysis
meshcore-decoder --structure 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172

# JSON output
meshcore-decoder --json 11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Build for production
npm run build

# Development with ts-node
npm run dev
```

## License

MIT License

Copyright (c) 2025 Michael Hart <michaelhart@michaelhart.me> (https://github.com/michaelhart)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.