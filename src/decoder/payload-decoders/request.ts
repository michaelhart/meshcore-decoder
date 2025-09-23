// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { RequestPayload } from '../../types/payloads';
import { PayloadSegment } from '../../types/packet';
import { PayloadType, PayloadVersion, RequestType } from '../../types/enums';
import { bytesToHex } from '../../utils/hex';

export class RequestPayloadDecoder {
  static decode(payload: Uint8Array, options?: { includeSegments?: boolean; segmentOffset?: number }): RequestPayload & { segments?: PayloadSegment[] } | null {
    try {
      // Based on MeshCore payloads.md - Request payload structure:
      // - timestamp (4 bytes, little endian)
      // - request_type (1 byte)
      // - request_data (rest of payload)
      
      if (payload.length < 5) {
        const result: RequestPayload & { segments?: PayloadSegment[] } = {
          type: PayloadType.Request,
          version: PayloadVersion.Version1,
          isValid: false,
          errors: ['Request payload too short (minimum 5 bytes: timestamp + request type)'],
          timestamp: 0,
          requestType: RequestType.GetStats,
          requestData: ''
        };
        
        if (options?.includeSegments) {
          result.segments = [{
            name: 'Invalid Request Data',
            description: 'Request payload too short (minimum 5 bytes required: 4 for timestamp + 1 for request type)',
            startByte: options.segmentOffset || 0,
            endByte: (options.segmentOffset || 0) + payload.length - 1,
            value: bytesToHex(payload)
          }];
        }
        
        return result;
      }

      const segments: PayloadSegment[] = [];
      const segmentOffset = options?.segmentOffset || 0;
      let offset = 0;

      // Parse timestamp (4 bytes, little endian)
      const timestamp = payload[0] | 
        (payload[1] << 8) | 
        (payload[2] << 16) | 
        (payload[3] << 24);
      
      if (options?.includeSegments) {
        const timestampHex = bytesToHex(payload.subarray(offset, offset + 4));
        const timestampDate = new Date(timestamp * 1000);
        segments.push({
          name: 'Timestamp',
          description: `Request timestamp (little-endian): ${timestamp} (0x${timestamp.toString(16)}) = ${timestampDate.toISOString()}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset + 3,
          value: timestampHex
        });
      }
      offset += 4;

      // Parse request type (1 byte)
      const requestTypeValue = payload[4];
      let requestType: RequestType;
      let requestTypeName = 'Unknown';
      
      switch (requestTypeValue) {
        case 0x01: 
          requestType = RequestType.GetStats; 
          requestTypeName = 'GetStats';
          break;
        case 0x02: 
          requestType = RequestType.Keepalive; 
          requestTypeName = 'Keepalive (deprecated)';
          break;
        case 0x03: 
          requestType = RequestType.GetTelemetryData; 
          requestTypeName = 'GetTelemetryData';
          break;
        case 0x04: 
          requestType = RequestType.GetMinMaxAvgData; 
          requestTypeName = 'GetMinMaxAvgData';
          break;
        case 0x05: 
          requestType = RequestType.GetAccessList; 
          requestTypeName = 'GetAccessList';
          break;
        case 0x2F: 
          requestType = RequestType.GetStats; 
          requestTypeName = 'GetStats (alt)';
          break;
        default: 
          requestType = RequestType.GetStats; 
          requestTypeName = `Unknown (0x${requestTypeValue.toString(16).padStart(2, '0')})`;
          break;
      }

      if (options?.includeSegments) {
        segments.push({
          name: 'Request Type',
          description: `Request type: ${requestTypeName}`,
          startByte: segmentOffset + offset,
          endByte: segmentOffset + offset,
          value: `0x${requestTypeValue.toString(16).padStart(2, '0')}`
        });
      }
      offset += 1;

      // Parse request data (remaining bytes)
      let requestData = '';
      if (payload.length > 5) {
        requestData = bytesToHex(payload.subarray(5));
        
        if (options?.includeSegments) {
          segments.push({
            name: 'Request Data',
            description: `Additional request data (${payload.length - 5} bytes)`,
            startByte: segmentOffset + offset,
            endByte: segmentOffset + payload.length - 1,
            value: requestData
          });
        }
      }

      const result: RequestPayload & { segments?: PayloadSegment[] } = {
        type: PayloadType.Request,
        version: PayloadVersion.Version1,
        isValid: true,
        timestamp,
        requestType,
        requestData
      };

      if (options?.includeSegments) {
        result.segments = segments;
      }

      return result;
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
