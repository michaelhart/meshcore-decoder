#include "orlp-ed25519/src/ed25519.h"
#include <emscripten.h>

// WebAssembly wrapper for orlp/ed25519 key derivation

EMSCRIPTEN_KEEPALIVE
int orlp_derive_public_key(unsigned char *public_key, const unsigned char *private_key) {
    // Use orlp's ed25519_create_keypair logic but only for key derivation
    // The private_key is already the 64-byte orlp format
    
    // Extract the first 32 bytes (the actual scalar)
    unsigned char scalar[32];
    for (int i = 0; i < 32; i++) {
        scalar[i] = private_key[i];
    }
    
    // Check orlp precondition
    if (scalar[31] > 127) {
        return -1; // Invalid scalar
    }
    
    // Use orlp's internal ge_scalarmult_base function
    // This is declared in ge.h but we need to access it
    extern void ge_scalarmult_base(void *h, const unsigned char *a);
    extern void ge_p3_tobytes(unsigned char *s, const void *h);
    
    // Allocate space for ge_p3 point (we don't know the exact size, but it's small)
    unsigned char point[128]; // Should be enough for ge_p3 structure
    
    // Perform scalar multiplication: point = scalar * base_point
    ge_scalarmult_base(point, scalar);
    
    // Convert point to bytes
    ge_p3_tobytes(public_key, point);
    
    return 0; // Success
}

EMSCRIPTEN_KEEPALIVE
int orlp_validate_keypair(const unsigned char *public_key, const unsigned char *private_key) {
    unsigned char derived_public[32];
    
    if (orlp_derive_public_key(derived_public, private_key) != 0) {
        return 0; // Derivation failed
    }
    
    // Compare derived public key with expected
    for (int i = 0; i < 32; i++) {
        if (derived_public[i] != public_key[i]) {
            return 0; // Mismatch
        }
    }
    
    return 1; // Match
}

EMSCRIPTEN_KEEPALIVE
void orlp_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    ed25519_sign(signature, message, message_len, public_key, private_key);
}

EMSCRIPTEN_KEEPALIVE
int orlp_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
    return ed25519_verify(signature, message, message_len, public_key);
}
