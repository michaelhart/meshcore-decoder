/**
 * Convert a single byte to uppercase hex string
 */
export function byteToHex(byte: number): string {
  return byte.toString(16).padStart(2, '0').toUpperCase();
}

/**
 * Convert a Uint8Array to uppercase hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(byteToHex).join('');
}

/**
 * Convert a number to uppercase hex string with specified padding
 */
export function numberToHex(num: number, padLength: number = 8): string {
  return (num >>> 0).toString(16).padStart(padLength, '0').toUpperCase();
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  // Remove any whitespace and convert to uppercase
  const cleanHex = hex.replace(/\s/g, '').toUpperCase();
  
  // Validate hex string
  if (!/^[0-9A-F]*$/.test(cleanHex)) {
    throw new Error(`Invalid hex string: invalid characters at position 0`);
  }
  
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string: odd length');
  }
  
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  
  return bytes;
}
