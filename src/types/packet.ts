import { RouteType, PayloadType, PayloadVersion } from './enums';
import { PayloadData } from './payloads';

// main decoded packet interface
export interface DecodedPacket {
  // packet metadata
  messageHash: string;
  
  // header information
  routeType: RouteType;
  payloadType: PayloadType;
  payloadVersion: PayloadVersion;
  
  // transport and routing
  transportCodes?: [number, number];
  pathLength: number;
  path: string[] | null;
  
  // payload data
  payload: {
    raw: string; // hex string
    decoded: PayloadData | null;
  };
  
  // metadata
  totalBytes: number;
  isValid: boolean;
  errors?: string[];
}

// interface for detailed structure analysis
export interface PacketStructure {
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

export interface PacketSegment {
  name: string;
  description: string;
  startByte: number;
  endByte: number;
  value: string;
  headerBreakdown?: HeaderBreakdown;
}

export interface PayloadSegment {
  name: string;
  description: string;
  startByte: number;
  endByte: number;
  value: string;
  decryptedMessage?: string;
}

export interface HeaderBreakdown {
  fullBinary: string;
  fields: Array<{
    bits: string;
    field: string;
    value: string;
    binary: string;
  }>;
}
