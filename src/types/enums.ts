// Reference: https://github.com/meshcore-dev/MeshCore/blob/main/docs/packet_structure.md

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
  Control = 0x0B,
  RawCustom = 0x0F
}

// Control packet sub-types (upper 4 bits of first payload byte)
export enum ControlSubType {
  NodeDiscoverReq = 0x80,
  NodeDiscoverResp = 0x90
}

export enum PayloadVersion {
  Version1 = 0x00,
  Version2 = 0x01,
  Version3 = 0x02,
  Version4 = 0x03
}

export enum DeviceRole {
  Unknown = 0x00,
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
