// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

import { RouteType, PayloadType, PayloadVersion, DeviceRole, RequestType } from '../types/enums';

/**
 * Get human-readable name for RouteType enum value
 */
export function getRouteTypeName(routeType: RouteType): string {
  switch (routeType) {
    case RouteType.Flood: return 'Flood';
    case RouteType.Direct: return 'Direct';
    case RouteType.TransportFlood: return 'TransportFlood';
    case RouteType.TransportDirect: return 'TransportDirect';
    default: return `Unknown (${routeType})`;
  }
}

/**
 * Get human-readable name for PayloadType enum value
 */
export function getPayloadTypeName(payloadType: PayloadType): string {
  switch (payloadType) {
    case PayloadType.RawCustom: return 'RawCustom';
    case PayloadType.Trace: return 'Trace';
    case PayloadType.Advert: return 'Advert';
    case PayloadType.GroupText: return 'GroupText';
    case PayloadType.GroupData: return 'GroupData';
    case PayloadType.Request: return 'Request';
    case PayloadType.Response: return 'Response';
    case PayloadType.TextMessage: return 'TextMessage';
    case PayloadType.AnonRequest: return 'AnonRequest';
    case PayloadType.Ack: return 'Ack';
    case PayloadType.Path: return 'Path';
    case PayloadType.Multipart: return 'Multipart';
    default: return `Unknown (${payloadType})`;
  }
}

/**
 * Get human-readable name for PayloadVersion enum value
 */
export function getPayloadVersionName(version: PayloadVersion): string {
  switch (version) {
    case PayloadVersion.Version1: return 'Version 1';
    case PayloadVersion.Version2: return 'Version 2';
    case PayloadVersion.Version3: return 'Version 3';
    case PayloadVersion.Version4: return 'Version 4';
    default: return `Unknown (${version})`;
  }
}

/**
 * Get human-readable name for DeviceRole enum value
 */
export function getDeviceRoleName(role: DeviceRole): string {
  switch (role) {
    case DeviceRole.ChatNode: return 'Chat Node';
    case DeviceRole.Repeater: return 'Repeater';
    case DeviceRole.RoomServer: return 'Room Server';
    case DeviceRole.Sensor: return 'Sensor';
    default: return `Unknown (${role})`;
  }
}

/**
 * Get human-readable name for RequestType enum value
 */
export function getRequestTypeName(requestType: RequestType): string {
  switch (requestType) {
    case RequestType.GetStats: return 'Get Stats';
    case RequestType.Keepalive: return 'Keepalive (deprecated)';
    case RequestType.GetTelemetryData: return 'Get Telemetry Data';
    case RequestType.GetMinMaxAvgData: return 'Get Min/Max/Avg Data';
    case RequestType.GetAccessList: return 'Get Access List';
    default: return `Unknown (${requestType})`;
  }
}
