// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License
//
// Region transport code calculation matching MeshCore firmware:
// - TransportKeyStore::getAutoKeyFor() — key = first 16 bytes of SHA256(regionName)
// - TransportKey::calcTransportCode() — HMAC-SHA256(key, payloadType || payload), first 2 bytes as LE uint16

import { SHA256, HmacSHA256, enc } from 'crypto-js';
import { hexToBytes, bytesToHex } from '../utils/hex';

/** Size of a region transport key in bytes (first 16 bytes of SHA256). */
export const REGION_KEY_SIZE = 16;

/**
 * Normalize region name for key derivation: prepend '#' if missing.
 * Matches MeshCore RegionMap::findMatch() "implicit auto hashtag region" behavior.
 */
export function normalizeRegionName(regionName: string): string {
  return regionName.startsWith('#') ? regionName : '#' + regionName;
}

/**
 * Compute the 16-byte region key from a region name (e.g. "#Europe", "Europe").
 * Matches MeshCore TransportKeyStore::getAutoKeyFor() for public hashtag regions:
 * key = first 16 bytes of SHA256(name). If name does not start with '#', it is
 * prepended (firmware "implicit auto hashtag region" behavior).
 *
 * @param regionName - Region name as used in firmware (e.g. "#Europe" or "Europe")
 * @returns 16-byte key
 */
export function calcRegionKey(regionName: string): Uint8Array {
  const name = normalizeRegionName(regionName);
  const hashHex = SHA256(enc.Utf8.parse(name)).toString(enc.Hex);
  const keyHex = hashHex.slice(0, REGION_KEY_SIZE * 2);
  return hexToBytes(keyHex);
}

/**
 * Compute the transport code for a given region key and packet payload.
 * Matches MeshCore TransportKey::calcTransportCode(): HMAC-SHA256(key, payloadType || payload),
 * first 2 bytes as little-endian uint16; 0 and 0xFFFF are reserved and nudge to 1 and 0xFFFE.
 *
 * @param regionKey - 16-byte region key (e.g. from calcRegionKey)
 * @param payloadType - Packet payload type (e.g. PayloadType.GroupText)
 * @param payload - Raw payload bytes (header and path are not included)
 * @returns 16-bit transport code
 */
export function calcTransportCode(
  regionKey: Uint8Array,
  payloadType: number,
  payload: Uint8Array
): number {
  const keyHex = bytesToHex(regionKey);
  const keyWords = enc.Hex.parse(keyHex);
  const message = new Uint8Array(1 + payload.length);
  message[0] = payloadType & 0xff;
  message.set(payload, 1);
  const messageHex = bytesToHex(message);
  const messageWords = enc.Hex.parse(messageHex);
  const hmac = HmacSHA256(messageWords, keyWords).toString(enc.Hex);
  const firstTwoBytes = hexToBytes(hmac.slice(0, 4));
  let code = firstTwoBytes[0]! | (firstTwoBytes[1]! << 8);
  if (code === 0) code = 1;
  else if (code === 0xffff) code = 0xfffe;
  return code & 0xffff;
}

/**
 * Compute the transport code for a region name and a given packet payload.
 * Convenience helper: calcRegionKey(name) then calcTransportCode(key, type, payload).
 *
 * @param regionName - Region name (e.g. "#Europe")
 * @param payloadType - Packet payload type
 * @param payload - Raw payload bytes
 * @returns 16-bit transport code
 */
export function calcTransportCodeForRegion(
  regionName: string,
  payloadType: number,
  payload: Uint8Array
): number {
  const key = calcRegionKey(regionName);
  return calcTransportCode(key, payloadType, payload);
}

/**
 * Check whether a decoded packet's first transport code matches the given region name.
 * Use for packets with route type TransportFlood or TransportDirect.
 *
 * @param regionName - Region name (e.g. "#Europe")
 * @param payloadType - Packet payload type
 * @param payloadRawHex - Payload bytes as hex (e.g. packet.payload.raw)
 * @param transportCode0 - First transport code from the packet (e.g. packet.transportCodes[0])
 * @returns true if the region's computed code equals transportCode0
 */
export function transportCodeMatchesRegion(
  regionName: string,
  payloadType: number,
  payloadRawHex: string,
  transportCode0: number
): boolean {
  const payload = hexToBytes(payloadRawHex);
  const code = calcTransportCodeForRegion(regionName, payloadType, payload);
  return (code & 0xffff) === (transportCode0 & 0xffff);
}
