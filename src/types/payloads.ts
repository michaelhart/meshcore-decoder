import { PayloadType, PayloadVersion, DeviceRole, RequestType } from './enums';

// Reference: https://github.com/meshcore-dev/MeshCore/blob/main/docs/payloads.md

export interface BasePayload {
  type: PayloadType;
  version: PayloadVersion;
  isValid: boolean;
  errors?: string[];
}

export interface AdvertPayload extends BasePayload {
  publicKey: string;
  timestamp: number;
  signature: string;
  appData: {
    flags: number;
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

export interface TracePayload extends BasePayload {
  traceTag: number;
  authCode: number;
  flags: number;
  pathHashes: string[];
  snrValues?: number[]; // from path field for TRACE packets
}

export interface GroupTextPayload extends BasePayload {
  channelHash: string;
  cipherMac: string;
  ciphertext: string; // raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    flags: number;
    sender?: string;
    message: string;
  };
}

export interface RequestPayload extends BasePayload {
  timestamp: number;
  requestType: RequestType;
  requestData?: string;
}

export interface TextMessagePayload extends BasePayload {
  destinationHash: string;
  sourceHash: string;
  cipherMac: string;
  ciphertext: string; // raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    flags: number;
    attempt: number;
    message: string;
  };
}

export interface AnonRequestPayload extends BasePayload {
  destinationHash: string;
  senderPublicKey: string;
  cipherMac: string;
  ciphertext: string; // raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    timestamp: number;
    syncTimestamp?: number; // room server only
    password: string;
  };
}

export interface AckPayload extends BasePayload {
  checksum: number;
}

export interface ResponsePayload extends BasePayload {
  destinationHash: string;
  sourceHash: string;
  cipherMac: string;
  ciphertext: string; // raw encrypted data as hex
  ciphertextLength: number;
  decrypted?: {
    tag: number;
    content: string;
  };
}

// union type for all payload types
export type PayloadData = 
  | AdvertPayload 
  | TracePayload 
  | GroupTextPayload 
  | RequestPayload 
  | TextMessagePayload 
  | AnonRequestPayload 
  | AckPayload 
  | ResponsePayload;
