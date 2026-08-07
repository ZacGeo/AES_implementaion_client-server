#pragma once

#include <string>
#include <vector>
#include <cstdint>

// ============================================================
//  AES-128 Implementation
//  Block size  : 128 bits (16 bytes)
//  Key size    : 128 bits (16 bytes)
//  Rounds      : 10
//  Mode        : CBC (Cipher Block Chaining)
//  Padding     : PKCS#7
//
//  GF(2^8) arithmetic uses the AES irreducible polynomial:
//  x^8 + x^4 + x^3 + x + 1  →  0x11B
// ============================================================

// AES fixed dimensions
static const int AES_BLOCK_SIZE  = 16;   // bytes per block
static const int AES_KEY_SIZE    = 16;   // bytes in key (128-bit)
static const int AES_ROUNDS      = 10;   // number of rounds
static const int AES_KEY_WORDS   = 4;    // 32-bit words in key
static const int AES_TOTAL_WORDS = 44;   // words in expanded key

// ── GF(2^8) arithmetic ───────────────────────────────────────

/**
 * Multiply two bytes in GF(2^8) using the AES irreducible polynomial.
 * Used by MixColumns and its inverse.
 * @param a first operand
 * @param b second operand
 * @return product in GF(2^8)
 */
uint8_t gf_multiply(uint8_t a, uint8_t b);

// ── AES Core Round Operations ─────────────────────────────────

/**
 * SubBytes — substitutes each byte using the AES S-Box.
 * Provides non-linearity (confusion).
 * @param state 4x4 byte matrix (modified in place)
 */
void subBytes(uint8_t state[4][4]);

/**
 * InvSubBytes — substitutes each byte using the inverse S-Box.
 * @param state 4x4 byte matrix (modified in place)
 */
void invSubBytes(uint8_t state[4][4]);

/**
 * ShiftRows — cyclically shifts each row left by its row index.
 * Row 0: no shift, Row 1: 1 left, Row 2: 2 left, Row 3: 3 left.
 * Provides diffusion across columns.
 * @param state 4x4 byte matrix (modified in place)
 */
void shiftRows(uint8_t state[4][4]);

/**
 * InvShiftRows — cyclically shifts each row right by its row index.
 * @param state 4x4 byte matrix (modified in place)
 */
void invShiftRows(uint8_t state[4][4]);

/**
 * MixColumns — multiplies each column by a fixed polynomial in GF(2^8).
 * Provides diffusion within columns.
 * @param state 4x4 byte matrix (modified in place)
 */
void mixColumns(uint8_t state[4][4]);

/**
 * InvMixColumns — inverse of MixColumns for decryption.
 * @param state 4x4 byte matrix (modified in place)
 */
void invMixColumns(uint8_t state[4][4]);

/**
 * AddRoundKey — XORs the state with the current round key.
 * Same operation for encrypt and decrypt (XOR is its own inverse).
 * @param state    4x4 byte matrix (modified in place)
 * @param roundKey pointer to 16 bytes of round key
 */
void addRoundKey(uint8_t state[4][4], const uint8_t* roundKey);

// ── Key Schedule ─────────────────────────────────────────────

/**
 * KeyExpansion — expands the 16-byte key into 44 words (176 bytes).
 * Produces one round key per AES round + the initial round key.
 * Uses SubWord, RotWord, and Rcon constants.
 * @param key          original 16-byte AES key
 * @param expandedKey  output array of 44 uint32_t words
 */
void keyExpansion(const uint8_t key[AES_KEY_SIZE],
                  uint32_t expandedKey[AES_TOTAL_WORDS]);

// ── Block Encrypt / Decrypt ───────────────────────────────────

/**
 * AES_EncryptBlock — encrypts exactly one 16-byte block.
 * Performs: AddRoundKey → 9x(SubBytes+ShiftRows+MixColumns+AddRoundKey)
 *           → SubBytes+ShiftRows+AddRoundKey
 * @param block       16 bytes of plaintext (modified in place → ciphertext)
 * @param expandedKey 44-word expanded key from keyExpansion()
 */
void AES_EncryptBlock(uint8_t block[AES_BLOCK_SIZE],
                      const uint32_t expandedKey[AES_TOTAL_WORDS]);

/**
 * AES_DecryptBlock — decrypts exactly one 16-byte block.
 * Performs the inverse round operations in reverse order.
 * @param block       16 bytes of ciphertext (modified in place → plaintext)
 * @param expandedKey 44-word expanded key from keyExpansion()
 */
void AES_DecryptBlock(uint8_t block[AES_BLOCK_SIZE],
                      const uint32_t expandedKey[AES_TOTAL_WORDS]);

// ── CBC Mode (what the clients actually use) ──────────────────

/**
 * AES_CBC_Encrypt — encrypts a plaintext string of any length.
 * - Applies PKCS#7 padding to make length a multiple of 16
 * - Generates a random 16-byte IV
 * - Prepends IV to the ciphertext (receiver needs it to decrypt)
 *
 * @param plaintext  the message to encrypt
 * @param key        16-byte AES key (must be exactly AES_KEY_SIZE bytes)
 * @return           IV (16 bytes) + ciphertext — ready to send over network
 */
std::string AES_CBC_Encrypt(const std::string& plaintext,
                             const uint8_t key[AES_KEY_SIZE]);

/**
 * AES_CBC_Decrypt — decrypts a ciphertext produced by AES_CBC_Encrypt.
 * - Extracts IV from the first 16 bytes
 * - Decrypts all blocks using CBC
 * - Removes PKCS#7 padding
 *
 * @param ciphertext  IV (16 bytes) + encrypted data
 * @param key         16-byte AES key (same key used to encrypt)
 * @return            original plaintext string
 */
std::string AES_CBC_Decrypt(const std::string& ciphertext,
                             const uint8_t key[AES_KEY_SIZE]);
