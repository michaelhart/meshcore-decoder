// MeshCore Packet Decoder
// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

export { MeshCorePacketDecoder } from './decoder/packet-decoder';
export { MeshCorePacketDecoder as MeshCoreDecoder } from './decoder/packet-decoder';

// Type exports
export type { DecodedPacket, PacketStructure, PacketSegment, PayloadSegment, HeaderBreakdown } from './types/packet';
export type { 
  BasePayload, 
  AdvertPayload, 
  TracePayload, 
  GroupTextPayload, 
  RequestPayload, 
  TextMessagePayload, 
  AnonRequestPayload, 
  AckPayload, 
  PathPayload,
  ResponsePayload,
  PayloadData 
} from './types/payloads';
export type { CryptoKeyStore, DecryptionOptions, DecryptionResult, ValidationResult } from './types/crypto';

// Enum exports
export { 
  RouteType, 
  PayloadType, 
  PayloadVersion, 
  DeviceRole, 
  AdvertFlags, 
  RequestType 
} from './types/enums';

// Crypto exports
export { MeshCoreKeyStore } from './crypto/key-manager';
export { ChannelCrypto } from './crypto/channel-crypto';
export { Ed25519SignatureVerifier } from './crypto/ed25519-verifier';

// Utility exports
export { hexToBytes, bytesToHex, byteToHex, numberToHex } from './utils/hex';
export { 
  getRouteTypeName, 
  getPayloadTypeName, 
  getPayloadVersionName, 
  getDeviceRoleName, 
  getRequestTypeName 
} from './utils/enum-names';

import * as EnumUtils from './utils/enum-names';
import * as HexUtils from './utils/hex';

export const Utils = {
  ...EnumUtils,
  ...HexUtils
};
