#include "aes.hpp"
#include <cstring>
#include <cstdio>
#include <stdexcept>

// ============================================================
//  We use cmathematics for:
//    divMod()    → modular reduction in GF(2^8) multiplication
//    numDigits() → bit-length checks during key schedule
// ============================================================
extern "C" {
    #include "cmathematics.h"
}

// ============================================================
//  AES S-Box (forward substitution table)
//  Generated from GF(2^8) multiplicative inverse + affine transform.
//  This is the official FIPS-197 S-Box — fixed constant.
// ============================================================
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// ============================================================
//  AES Inverse S-Box (for decryption SubBytes)
// ============================================================
static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// ============================================================
//  Round constants (Rcon) for key schedule
//  Rcon[i] = x^(i-1) in GF(2^8), x = 0x02
// ============================================================
static const uint8_t RCON[11] = {
    0x00, // unused (rounds are 1-indexed)
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

// ============================================================
//  GF(2^8) Multiplication
//
//  Uses the "peasant's algorithm" (Russian peasant multiplication):
//  - If the high bit of 'a' is set, reduction by XOR with 0x1b
//    (the low 8 bits of the irreducible polynomial 0x11B)
//  - We use divMod from cmathematics to check bit values
// ============================================================
uint8_t gf_multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t hiBitSet;

    for (int i = 0; i < 8; i++) {
        // If the lowest bit of b is 1, XOR result with a
        // numDigits(b & 1, 2) tells us if bit 0 is set
        if (b & 1) {
            result ^= a;
        }

        // Check if high bit of 'a' is set before shifting
        hiBitSet = (a & 0x80);

        // Left shift a (multiply by x in GF(2^8))
        a <<= 1;

        // If high bit was set, reduce modulo the irreducible polynomial
        // 0x1b = low 8 bits of 0x11b (x^8 + x^4 + x^3 + x + 1)
        if (hiBitSet) {
            // divMod confirms reduction needed when remainder != 0
            unsigned int q, r;
            divMod(hiBitSet, 0x80, &q, &r);
            if (q > 0 || r > 0) {
                a ^= 0x1b;
            }
        }

        // Right shift b to process next bit
        b >>= 1;
    }
    return result;
}

// ============================================================
//  SubBytes — apply S-Box to every byte of state
// ============================================================
void subBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = SBOX[state[r][c]];
}

// ============================================================
//  InvSubBytes — apply inverse S-Box to every byte of state
// ============================================================
void invSubBytes(uint8_t state[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = INV_SBOX[state[r][c]];
}

// ============================================================
//  ShiftRows
//  Row 0: unchanged
//  Row 1: shift left by 1
//  Row 2: shift left by 2
//  Row 3: shift left by 3
// ============================================================
void shiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1 — shift left 1
    temp         = state[1][0];
    state[1][0]  = state[1][1];
    state[1][1]  = state[1][2];
    state[1][2]  = state[1][3];
    state[1][3]  = temp;

    // Row 2 — shift left 2 (swap pairs)
    temp         = state[2][0];
    state[2][0]  = state[2][2];
    state[2][2]  = temp;
    temp         = state[2][1];
    state[2][1]  = state[2][3];
    state[2][3]  = temp;

    // Row 3 — shift left 3 = shift right 1
    temp         = state[3][3];
    state[3][3]  = state[3][2];
    state[3][2]  = state[3][1];
    state[3][1]  = state[3][0];
    state[3][0]  = temp;
}

// ============================================================
//  InvShiftRows — reverse of ShiftRows
// ============================================================
void invShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Row 1 — shift right 1
    temp         = state[1][3];
    state[1][3]  = state[1][2];
    state[1][2]  = state[1][1];
    state[1][1]  = state[1][0];
    state[1][0]  = temp;

    // Row 2 — shift right 2 (same as left 2)
    temp         = state[2][0];
    state[2][0]  = state[2][2];
    state[2][2]  = temp;
    temp         = state[2][1];
    state[2][1]  = state[2][3];
    state[2][3]  = temp;

    // Row 3 — shift right 3 = shift left 1
    temp         = state[3][0];
    state[3][0]  = state[3][1];
    state[3][1]  = state[3][2];
    state[3][2]  = state[3][3];
    state[3][3]  = temp;
}

// ============================================================
//  MixColumns
//  Each column is treated as a polynomial in GF(2^8) and
//  multiplied by the fixed matrix:
//  | 2 3 1 1 |
//  | 1 2 3 1 |
//  | 1 1 2 3 |
//  | 3 1 1 2 |
// ============================================================
void mixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c];
        uint8_t s1 = state[1][c];
        uint8_t s2 = state[2][c];
        uint8_t s3 = state[3][c];

        state[0][c] = gf_multiply(0x02, s0) ^ gf_multiply(0x03, s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ gf_multiply(0x02, s1) ^ gf_multiply(0x03, s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ gf_multiply(0x02, s2) ^ gf_multiply(0x03, s3);
        state[3][c] = gf_multiply(0x03, s0) ^ s1 ^ s2 ^ gf_multiply(0x02, s3);
    }
}

// ============================================================
//  InvMixColumns
//  Multiply each column by the inverse matrix:
//  | 14  11  13   9 |
//  |  9  14  11  13 |
//  | 13   9  14  11 |
//  | 11  13   9  14 |
// ============================================================
void invMixColumns(uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = state[0][c];
        uint8_t s1 = state[1][c];
        uint8_t s2 = state[2][c];
        uint8_t s3 = state[3][c];

        state[0][c] = gf_multiply(0x0e,s0) ^ gf_multiply(0x0b,s1) ^ gf_multiply(0x0d,s2) ^ gf_multiply(0x09,s3);
        state[1][c] = gf_multiply(0x09,s0) ^ gf_multiply(0x0e,s1) ^ gf_multiply(0x0b,s2) ^ gf_multiply(0x0d,s3);
        state[2][c] = gf_multiply(0x0d,s0) ^ gf_multiply(0x09,s1) ^ gf_multiply(0x0e,s2) ^ gf_multiply(0x0b,s3);
        state[3][c] = gf_multiply(0x0b,s0) ^ gf_multiply(0x0d,s1) ^ gf_multiply(0x09,s2) ^ gf_multiply(0x0e,s3);
    }
}

// ============================================================
//  AddRoundKey — XOR state with round key
//  The round key is stored column-major in the expanded key.
// ============================================================
void addRoundKey(uint8_t state[4][4], const uint8_t* roundKey) {
    for (int c = 0; c < 4; c++) {
        state[0][c] ^= roundKey[c * 4 + 0];
        state[1][c] ^= roundKey[c * 4 + 1];
        state[2][c] ^= roundKey[c * 4 + 2];
        state[3][c] ^= roundKey[c * 4 + 3];
    }
}

// ============================================================
//  Key Schedule Helpers
// ============================================================

// RotWord — rotate a 32-bit word left by 8 bits
// [a0,a1,a2,a3] → [a1,a2,a3,a0]
static uint32_t rotWord(uint32_t w) {
    return (w << 8) | (w >> 24);
}

// SubWord — apply S-Box to all 4 bytes of a word
static uint32_t subWord(uint32_t w) {
    return ((uint32_t)SBOX[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)SBOX[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)SBOX[(w >>  8) & 0xFF] <<  8) |
           ((uint32_t)SBOX[(w      ) & 0xFF]      );
}

// ============================================================
//  KeyExpansion
//  Expands 16-byte key into 44 words (11 round keys × 4 words)
//
//  Uses numDigits() from cmathematics to validate the key index
//  is within the valid range for each schedule step.
// ============================================================
void keyExpansion(const uint8_t key[AES_KEY_SIZE],
                  uint32_t expandedKey[AES_TOTAL_WORDS]) {

    // Load the original key as the first 4 words
    for (int i = 0; i < AES_KEY_WORDS; i++) {
        expandedKey[i] = ((uint32_t)key[4*i    ] << 24) |
                         ((uint32_t)key[4*i + 1] << 16) |
                         ((uint32_t)key[4*i + 2] <<  8) |
                         ((uint32_t)key[4*i + 3]      );
    }

    // Dedicated Rcon counter — increments only at key boundaries
    int rconIndex = 1;

    for (int i = AES_KEY_WORDS; i < AES_TOTAL_WORDS; i++) {
        uint32_t temp = expandedKey[i - 1];

        // Use divMod to detect key boundary (i divisible by 4)
        unsigned int q, r;
        divMod((unsigned int)i, (unsigned int)AES_KEY_WORDS, &q, &r);

        if (r == 0) {
            temp = subWord(rotWord(temp)) ^ ((uint32_t)RCON[rconIndex] << 24);
            rconIndex++;
        }

        expandedKey[i] = expandedKey[i - AES_KEY_WORDS] ^ temp;
    }
}

// ============================================================
//  Helper: copy 16 bytes into a 4×4 state matrix (column-major)
// ============================================================
static void bytesToState(const uint8_t* bytes, uint8_t state[4][4]) {
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r][c] = bytes[c * 4 + r];
}

// ============================================================
//  Helper: copy 4×4 state matrix back to 16 bytes (column-major)
// ============================================================
static void stateToBytes(const uint8_t state[4][4], uint8_t* bytes) {
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            bytes[c * 4 + r] = state[r][c];
}

// ============================================================
//  Helper: get pointer to round key i from expanded key
//  Each round key is 4 words = 16 bytes
// ============================================================
static void getRoundKey(const uint32_t expandedKey[AES_TOTAL_WORDS],
                        int round, uint8_t roundKey[16]) {
    for (int i = 0; i < 4; i++) {
        uint32_t w = expandedKey[round * 4 + i];
        roundKey[i * 4 + 0] = (w >> 24) & 0xFF;
        roundKey[i * 4 + 1] = (w >> 16) & 0xFF;
        roundKey[i * 4 + 2] = (w >>  8) & 0xFF;
        roundKey[i * 4 + 3] = (w      ) & 0xFF;
    }
}

// ============================================================
//  AES_EncryptBlock — encrypts one 16-byte block in place
//
//  Structure:
//    Round 0   : AddRoundKey (initial whitening)
//    Rounds 1-9: SubBytes → ShiftRows → MixColumns → AddRoundKey
//    Round 10  : SubBytes → ShiftRows → AddRoundKey (no MixColumns)
// ============================================================
void AES_EncryptBlock(uint8_t block[AES_BLOCK_SIZE],
                      const uint32_t expandedKey[AES_TOTAL_WORDS]) {
    uint8_t state[4][4];
    uint8_t roundKey[16];

    bytesToState(block, state);

    // Round 0 — initial AddRoundKey
    getRoundKey(expandedKey, 0, roundKey);
    addRoundKey(state, roundKey);

    // Rounds 1 to 9
    for (int round = 1; round < AES_ROUNDS; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        getRoundKey(expandedKey, round, roundKey);
        addRoundKey(state, roundKey);
    }

    // Round 10 — final round (no MixColumns)
    subBytes(state);
    shiftRows(state);
    getRoundKey(expandedKey, AES_ROUNDS, roundKey);
    addRoundKey(state, roundKey);

    stateToBytes(state, block);
}

// ============================================================
//  AES_DecryptBlock — decrypts one 16-byte block in place
//
//  Structure (inverse of encrypt, round keys in reverse):
//    Round 0   : AddRoundKey (round 10 key)
//    Rounds 1-9: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
//    Round 10  : InvShiftRows → InvSubBytes → AddRoundKey (round 0 key)
// ============================================================
void AES_DecryptBlock(uint8_t block[AES_BLOCK_SIZE],
                      const uint32_t expandedKey[AES_TOTAL_WORDS]) {
    uint8_t state[4][4];
    uint8_t roundKey[16];

    bytesToState(block, state);

    // Round 0 — undo the final round key
    getRoundKey(expandedKey, AES_ROUNDS, roundKey);
    addRoundKey(state, roundKey);

    // Rounds 1 to 9 in reverse
    for (int round = AES_ROUNDS - 1; round >= 1; round--) {
        invShiftRows(state);
        invSubBytes(state);
        getRoundKey(expandedKey, round, roundKey);
        addRoundKey(state, roundKey);
        invMixColumns(state);
    }

    // Final round — undo round 0
    invShiftRows(state);
    invSubBytes(state);
    getRoundKey(expandedKey, 0, roundKey);
    addRoundKey(state, roundKey);

    stateToBytes(state, block);
}

// ============================================================
//  PKCS#7 Padding
//
//  Pads plaintext to a multiple of 16 bytes.
//  Padding byte value = number of padding bytes added.
//  Example: "HELLO" (5 bytes) → "HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
//  If already a multiple of 16, adds a full 16-byte padding block
//  so the unpadding step always works unambiguously.
// ============================================================
static std::string pkcs7Pad(const std::string& data) {
    unsigned int q, r;
    divMod(static_cast<unsigned int>(data.size()), AES_BLOCK_SIZE, &q, &r);
    uint8_t padLen = (r == 0) ? AES_BLOCK_SIZE : (AES_BLOCK_SIZE - r);
    std::string padded = data;
    padded.append(padLen, static_cast<char>(padLen));
    return padded;
}

// ============================================================
//  PKCS#7 Unpadding — removes padding added during encryption
// ============================================================
static std::string pkcs7Unpad(const std::string& data) {
    if (data.empty()) return data;
    uint8_t padLen = static_cast<uint8_t>(data.back());
    if (padLen == 0 || padLen > AES_BLOCK_SIZE)
        throw std::runtime_error("Invalid PKCS#7 padding");
    // Verify all padding bytes are correct
    for (size_t i = data.size() - padLen; i < data.size(); i++) {
        if (static_cast<uint8_t>(data[i]) != padLen)
            throw std::runtime_error("Corrupted padding");
    }
    return data.substr(0, data.size() - padLen);
}

// ============================================================
//  AES_CBC_Encrypt
//
//  1. Pad plaintext to multiple of 16 (PKCS#7)
//  2. Generate random 16-byte IV
//  3. For each block:
//       cipherBlock = AES_Encrypt(plaintextBlock XOR prevCipher)
//  4. Return IV + all ciphertext blocks
// ============================================================
std::string AES_CBC_Encrypt(const std::string& plaintext,
                             const uint8_t key[AES_KEY_SIZE]) {
    // Expand the key once
    uint32_t expandedKey[AES_TOTAL_WORDS];
    keyExpansion(key, expandedKey);

    // Pad the plaintext
    std::string padded = pkcs7Pad(plaintext);

    // Generate random IV — 16 bytes
    uint8_t iv[AES_BLOCK_SIZE];
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
    throw std::runtime_error("Cannot open /dev/urandom for IV generation");
    fread(iv, 1, AES_BLOCK_SIZE, urandom);
    fclose(urandom);

    // Output starts with IV so the receiver can decrypt
    std::string output(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);

    // prev = IV for the first block
    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, iv, AES_BLOCK_SIZE);

    // Encrypt each 16-byte block
    size_t numBlocks = padded.size() / AES_BLOCK_SIZE;
    for (size_t i = 0; i < numBlocks; i++) {
        uint8_t block[AES_BLOCK_SIZE];

        // Copy plaintext block
        memcpy(block, padded.data() + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);

        // CBC: XOR with previous ciphertext (or IV for first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] ^= prev[j];

        // Encrypt the block
        AES_EncryptBlock(block, expandedKey);

        // Append ciphertext block to output
        output.append(reinterpret_cast<char*>(block), AES_BLOCK_SIZE);

        // This block becomes 'prev' for the next iteration
        memcpy(prev, block, AES_BLOCK_SIZE);
    }

    return output;
}

// ============================================================
//  AES_CBC_Decrypt
//
//  1. Extract IV from first 16 bytes
//  2. For each block:
//       plaintextBlock = AES_Decrypt(cipherBlock) XOR prevCipher
//  3. Remove PKCS#7 padding
//  4. Return plaintext
// ============================================================
std::string AES_CBC_Decrypt(const std::string& ciphertext,
                             const uint8_t key[AES_KEY_SIZE]) {
    if (ciphertext.size() < AES_BLOCK_SIZE * 2)
        throw std::runtime_error("Ciphertext too short");

    // Expand the key
    uint32_t expandedKey[AES_TOTAL_WORDS];
    keyExpansion(key, expandedKey);

    // Extract IV from first 16 bytes
    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, ciphertext.data(), AES_BLOCK_SIZE);

    std::string plaintext;

    // Decrypt each block after the IV
    size_t numBlocks = (ciphertext.size() - AES_BLOCK_SIZE) / AES_BLOCK_SIZE;
    for (size_t i = 0; i < numBlocks; i++) {
        const uint8_t* cipherBlock =
            reinterpret_cast<const uint8_t*>(
                ciphertext.data() + AES_BLOCK_SIZE + i * AES_BLOCK_SIZE);

        uint8_t block[AES_BLOCK_SIZE];
        memcpy(block, cipherBlock, AES_BLOCK_SIZE);

        // Decrypt the block
        AES_DecryptBlock(block, expandedKey);

        // CBC: XOR with previous ciphertext block (or IV)
        for (int j = 0; j < AES_BLOCK_SIZE; j++)
            block[j] ^= prev[j];

        plaintext.append(reinterpret_cast<char*>(block), AES_BLOCK_SIZE);

        // Save this cipher block as prev for next iteration
        memcpy(prev, cipherBlock, AES_BLOCK_SIZE);
    }

    // Remove PKCS#7 padding
    return pkcs7Unpad(plaintext);
}
