// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { RequestPayload } from '../../types/payloads';
import { PayloadType, PayloadVersion, RequestType } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class RequestPayloadDecoder {
  static decode(payload: Uint8Array): RequestPayload | null {
    try {
      // Based on MeshCore payloads.md - Request payload structure:
      // - timestamp (4 bytes, little endian)
      // - request_type (1 byte)
      // - request_data (rest of payload)
      
      if (payload.length < 5) {
        return {
          type: PayloadType.Request,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Request payload too short (minimum 5 bytes: timestamp + request type)'],
          timestamp: 0,
          requestType: RequestType.GetStats,
          requestData: ''
        };
      }

      // Parse timestamp (4 bytes, little endian)
      const timestamp = payload[0] | 
        (payload[1] << 8) | 
        (payload[2] << 16) | 
        (payload[3] << 24);

      // Parse request type (1 byte)
      const requestTypeValue = payload[4];
      let requestType: RequestType;
      switch (requestTypeValue) {
        case 0x01: requestType = RequestType.GetStats; break;
        case 0x02: requestType = RequestType.Keepalive; break;
        case 0x03: requestType = RequestType.GetTelemetryData; break;
        case 0x04: requestType = RequestType.GetMinMaxAvgData; break;
        case 0x05: requestType = RequestType.GetAccessList; break;
        case 0x2F: requestType = RequestType.GetStats; break;
        default: requestType = RequestType.GetStats; break;
      }

      // Parse request data (remaining bytes)
      let requestData = '';
      if (payload.length > 5) {
        requestData = bytesToHex(payload.subarray(5));
      }

      return {
        type: PayloadType.Request,
        version: PayloadVersion.Version1,
        isValid: true,
        timestamp,
        requestType,
        requestData
      };
    } catch (error) {
      return {
        type: PayloadType.Request,
        version: PayloadVersion.Version1,
        isValid: false,
        errors: [error instanceof Error ? error.message : 'Failed to decode request payload'],
        timestamp: 0,
        requestType: RequestType.GetStats,
        requestData: ''
      };
    }
  }

}
