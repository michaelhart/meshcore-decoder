# MeshCore Decoder

A TypeScript library for decoding MeshCore mesh networking packets with full cryptographic support.

## Features

- **Packet Decoding**: Decode MeshCore packets
- **Built-in Decryption**: Decrypt GroupText, TextMessage, and other encrypted payloads
- **Developer Friendly**: TypeScript-first with full type safety and portability of JavaScript

## Installation

```bash
npm install meshcore-decoder
```

## Quick Start

```typescript
import { MeshCorePacketDecoder, PayloadType, DeviceRole } from 'meshcore-decoder';

// Decode a MeshCore packet
const hexData = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

const packet = MeshCorePacketDecoder.decode(hexData);

console.log(`Route Type: ${packet.routeType}`);
console.log(`Payload Type: ${packet.payloadType}`);
console.log(`Message Hash: ${packet.messageHash}`);

if (packet.payloadType === PayloadType.Advert && packet.payload.decoded) {
  const advert = packet.payload.decoded;
  console.log(`Device Name: ${advert.appData.name}`);
  console.log(`Device Role: ${DeviceRole[advert.appData.deviceRole]}`);
  if (advert.appData.location) {
    console.log(`Location: ${advert.appData.location.latitude}, ${advert.appData.location.longitude}`);
  }
}
```

## Full Packet Structure Example

Here's what a complete decoded packet looks like:

```typescript
import { MeshCorePacketDecoder } from 'meshcore-decoder';

const hexData = '11007E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C94006CE7CF682E58408DD8FCC51906ECA98EBF94A037886BDADE7ECD09FD92B839491DF3809C9454F5286D1D3370AC31A34593D569E9A042A3B41FD331DFFB7E18599CE1E60992A076D50238C5B8F85757375354522F50756765744D65736820436F75676172';

const packet = MeshCorePacketDecoder.decode(hexData);

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

| Value | Name | Description | Decoding | Decryption |
|-------|------|-------------|----------|------------|
| `0x00` | Request | Request (destination/source hashes + MAC) | ✅ | 🚧 |
| `0x01` | Response | Response to REQ or ANON_REQ | ✅ | 🚧 |
| `0x02` | Plain text message | Plain text message | ✅ | 🚧 |
| `0x03` | Acknowledgment | Acknowledgment | ✅ | N/A |
| `0x04` | Node advertisement | Node advertisement | ✅ | N/A |
| `0x05` | Group text message | Group text message | ✅ | ✅ |
| `0x06` | Group datagram | Group datagram | 🚧 | 🚧 |
| `0x07` | Anonymous request | Anonymous request | ✅ | 🚧 |
| `0x08` | Returned path | Returned path | ✅ | N/A |
| `0x09` | Trace | Trace a path, collecting SNI for each hop | ✅ | N/A |
| `0x0A` | Multi-part packet | Packet is part of a sequence of packets | 🚧 | 🚧 |
| `0x0F` | Custom packet | Custom packet (raw bytes, custom encryption) | 🚧 | 🚧 |

**Legend:**
- ✅ Fully implemented
- 🚧 Planned/In development
- `-` Not applicable

For some packet types not yet supported here, they may not exist in MeshCore yet or I have yet to observe these packet types on the mesh.

## Decryption Support

Simply provide your channel secret keys and the library handles everything else:

```typescript
// Create a key store with channel secret keys
const keyStore = MeshCorePacketDecoder.createKeyStore({
  channelSecrets: [
    '8b3387e9c5cdea6ac9e5edbaa115cd72', // Public channel (channel hash 11)
    'ff2b7d74e8d20f71505bda9ea8d59a1c', // A different channel's secret
  ]
});

// Decode encrypted GroupText message
const encryptedPacket = MeshCorePacketDecoder.decode(groupTextHexData, { keyStore });

if (encryptedPacket.payloadType === PayloadType.GroupText && encryptedPacket.payload.decoded) {
  const groupText = encryptedPacket.payload.decoded;
  
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