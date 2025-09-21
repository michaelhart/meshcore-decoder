// Copyright (c) 2025 Michael Hart: https://github.com/michaelhart/meshcore-decoder
// MIT License

export interface CryptoKeyStore {
  // node keys for TextMessage/Request decryption
  nodeKeys: Map<string, string>; // nodePublicKey -> privateKey (hex)
  
  // add/update keys
  addNodeKey(publicKey: string, privateKey: string): void;
  
  // check if keys are available
  hasChannelKey(channelHash: string): boolean;
  hasNodeKey(publicKey: string): boolean;
  getChannelKeys(channelHash: string): string[];
}

export interface DecryptionOptions {
  keyStore?: CryptoKeyStore;
  attemptDecryption?: boolean; // default: true if keyStore provided
  includeRawCiphertext?: boolean; // default: true
}

export interface DecryptionResult {
  success: boolean;
  data?: any;
  error?: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors?: string[];
}
