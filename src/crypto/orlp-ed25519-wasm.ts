// WebAssembly wrapper for orlp/ed25519 key derivation
// This provides the exact orlp algorithm for JavaScript

import { hexToBytes, bytesToHex } from '../utils/hex';

// Import the generated WASM module
const OrlpEd25519 = require('../../lib/orlp-ed25519.js');

let wasmModule: any = null;

/**
 * Initialize the orlp/ed25519 WebAssembly module
 */
async function initWasm(): Promise<void> {
  if (!wasmModule) {
    wasmModule = await OrlpEd25519();
  }
}

/**
 * Derive Ed25519 public key from private key using the exact orlp/ed25519 algorithm
 * 
 * @param privateKeyHex - 64-byte private key in hex format (orlp/ed25519 format)
 * @returns 32-byte public key in hex format
 */
export async function derivePublicKey(privateKeyHex: string): Promise<string> {
  await initWasm();
  
  const privateKeyBytes = hexToBytes(privateKeyHex);
  
  if (privateKeyBytes.length !== 64) {
    throw new Error(`Invalid private key length: expected 64 bytes, got ${privateKeyBytes.length}`);
  }
  
  // Allocate memory buffers directly in WASM heap
  const privateKeyPtr = 1024; // Use fixed memory locations
  const publicKeyPtr = 1024 + 64;
  
  // Copy private key to WASM memory
  wasmModule.HEAPU8.set(privateKeyBytes, privateKeyPtr);
  
  // Call the orlp key derivation function
  const result = wasmModule.ccall(
    'orlp_derive_public_key',
    'number',
    ['number', 'number'],
    [publicKeyPtr, privateKeyPtr]
  );
  
  if (result !== 0) {
    throw new Error('orlp key derivation failed: invalid private key');
  }
  
  // Read the public key from WASM memory
  const publicKeyBytes = new Uint8Array(32);
  publicKeyBytes.set(wasmModule.HEAPU8.subarray(publicKeyPtr, publicKeyPtr + 32));
  
  return bytesToHex(publicKeyBytes);
}

/**
 * Validate that a private key and public key pair match using orlp/ed25519
 * 
 * @param privateKeyHex - 64-byte private key in hex format
 * @param expectedPublicKeyHex - 32-byte public key in hex format
 * @returns true if the keys match, false otherwise
 */
export async function validateKeyPair(privateKeyHex: string, expectedPublicKeyHex: string): Promise<boolean> {
  try {
    await initWasm();
    
    const privateKeyBytes = hexToBytes(privateKeyHex);
    const expectedPublicKeyBytes = hexToBytes(expectedPublicKeyHex);
    
    if (privateKeyBytes.length !== 64) {
      return false;
    }
    
    if (expectedPublicKeyBytes.length !== 32) {
      return false;
    }
    
    // Allocate memory buffers directly in WASM heap
    const privateKeyPtr = 2048; // Use different fixed memory locations
    const publicKeyPtr = 2048 + 64;
    
    // Copy keys to WASM memory
    wasmModule.HEAPU8.set(privateKeyBytes, privateKeyPtr);
    wasmModule.HEAPU8.set(expectedPublicKeyBytes, publicKeyPtr);
    
    // Call the validation function (note: C function expects public_key first, then private_key)
    const result = wasmModule.ccall(
      'orlp_validate_keypair',
      'number',
      ['number', 'number'],
      [publicKeyPtr, privateKeyPtr]
    );
    
    return result === 1;
  } catch (error) {
    // Invalid hex strings or other errors should return false
    return false;
  }
}
