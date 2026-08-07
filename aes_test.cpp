#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include "aes.hpp"

// ANSI colors
#define GREEN  "\033[1;32m"
#define RED    "\033[1;31m"
#define YELLOW "\033[1;33m"
#define CYAN   "\033[1;36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

// ── Print a byte array as hex ─────────────────────────────────
void printHex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)data[i] << " ";
    std::cout << std::dec << "\n";
}

void printHexStr(const std::string& label, const std::string& data) {
    printHex(label,
             reinterpret_cast<const uint8_t*>(data.data()),
             data.size());
}

// ── Compare two byte arrays ───────────────────────────────────
bool bytesEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

int passed = 0;
int failed = 0;

void reportTest(const std::string& name, bool ok) {
    if (ok) {
        std::cout << GREEN << "  [PASS] " << RESET << name << "\n";
        passed++;
    } else {
        std::cout << RED   << "  [FAIL] " << RESET << name << "\n";
        failed++;
    }
}

// ============================================================
//  TEST 1 — GF(2^8) Multiplication
//  Known values from FIPS-197 appendix
// ============================================================
void testGFMultiply() {
    std::cout << CYAN << BOLD << "\n[1] GF(2^8) Multiplication\n" << RESET;

    reportTest("gf_multiply(0x57, 0x83) == 0xc1",
               gf_multiply(0x57, 0x83) == 0xc1);

    reportTest("gf_multiply(0x02, 0x87) == 0x15",
               gf_multiply(0x02, 0x87) == 0x15);

    reportTest("gf_multiply(0x03, 0x87) == 0x92",
               gf_multiply(0x03, 0x87) == 0x92);

    reportTest("gf_multiply(0x01, 0xAB) == 0xAB (identity)",
               gf_multiply(0x01, 0xAB) == 0xAB);
}

// ============================================================
//  TEST 2 — Key Expansion
//  Official NIST FIPS-197 Appendix A.1 test vector
//  Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
// ============================================================
void testKeyExpansion() {
    std::cout << CYAN << BOLD << "\n[2] Key Expansion (NIST FIPS-197 Appendix A.1)\n" << RESET;

    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    uint32_t expandedKey[44];
    keyExpansion(key, expandedKey);

    uint32_t nist[44] = {
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
        0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
        0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
        0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
        0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
        0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
        0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
        0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
        0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
        0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
        0x13111d7f, 0xe3944a17, 0xf307a78b, 0x4d2b30c5
    };

    printf("\n  Scanning for first divergence:\n");
    for (int w = 0; w < 44; w++) {
        bool match = (expandedKey[w] == nist[w]);
        printf("  W%02d: got %08x | expected %08x %s\n",
               w, expandedKey[w], nist[w], match ? "OK" : "<-- FIRST WRONG WORD");
        if (!match) break;
    }

    // rest of the function stays exactly the same...
    uint32_t expectedW4 = 0xa0fafe17;
}

// ============================================================
//  TEST 3 — Full Block Encrypt
//  NIST FIPS-197 Appendix B
//  Key:       2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
//  Plaintext: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
//  Expected:  39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
// ============================================================
void testBlockEncrypt() {
    std::cout << CYAN << BOLD << "\n[3] Block Encrypt (NIST FIPS-197 Appendix B)\n" << RESET;

    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    uint8_t block[16] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    };

    uint8_t expected[16] = {
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32
    };

    uint32_t expandedKey[44];
    keyExpansion(key, expandedKey);

    printHex("  Plaintext : ", block, 16);

    AES_EncryptBlock(block, expandedKey);

    printHex("  Encrypted : ", block, 16);
    printHex("  Expected  : ", expected, 16);

    reportTest("Ciphertext matches NIST vector",
               bytesEqual(block, expected, 16));
}

// ============================================================
//  TEST 4 — Full Block Decrypt
//  Reverse of Test 3
// ============================================================
void testBlockDecrypt() {
    std::cout << CYAN << BOLD << "\n[4] Block Decrypt (NIST FIPS-197 Appendix B reversed)\n" << RESET;

    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    // Start from the ciphertext
    uint8_t block[16] = {
        0x39,0x25,0x84,0x1d, 0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97, 0x19,0x6a,0x0b,0x32
    };

    uint8_t expected[16] = {
        0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
    };

    uint32_t expandedKey[44];
    keyExpansion(key, expandedKey);

    printHex("  Ciphertext: ", block, 16);

    AES_DecryptBlock(block, expandedKey);

    printHex("  Decrypted : ", block, 16);
    printHex("  Expected  : ", expected, 16);

    reportTest("Plaintext matches original",
               bytesEqual(block, expected, 16));
}

// ============================================================
//  TEST 5 — CBC Encrypt/Decrypt Round Trip
//  Verifies that decrypt(encrypt(msg)) == msg
//  Tests with messages of different lengths
// ============================================================
void testCBCRoundTrip() {
    std::cout << CYAN << BOLD << "\n[5] CBC Encrypt → Decrypt Round Trip\n" << RESET;

    // The shared key both clients will use
    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    // Test a: short message (less than 16 bytes)
    {
        std::string msg = "Hello Bob!";
        std::string cipher = AES_CBC_Encrypt(msg, key);
        std::string decrypted = AES_CBC_Decrypt(cipher, key);

        std::cout << "  Original  : \"" << msg << "\"\n";
        printHexStr("  Encrypted : ", cipher);
        std::cout << "  Decrypted : \"" << decrypted << "\"\n";
        reportTest("Short message round trip", decrypted == msg);
    }

    // Test b: exactly 16 bytes (one full block)
    {
        std::string msg = "1234567890ABCDEF";  // exactly 16 bytes
        std::string cipher = AES_CBC_Encrypt(msg, key);
        std::string decrypted = AES_CBC_Decrypt(cipher, key);
        reportTest("Exactly 16 bytes round trip", decrypted == msg);
    }

    // Test c: longer message (multiple blocks)
    {
        std::string msg = "Alice: This is a longer message that spans multiple AES blocks!";
        std::string cipher = AES_CBC_Encrypt(msg, key);
        std::string decrypted = AES_CBC_Decrypt(cipher, key);
        reportTest("Multi-block message round trip", decrypted == msg);
    }

    // Test d: empty-ish single char
    {
        std::string msg = "A";
        std::string cipher = AES_CBC_Encrypt(msg, key);
        std::string decrypted = AES_CBC_Decrypt(cipher, key);
        reportTest("Single character round trip", decrypted == msg);
    }

    // Test e: typical chat message format
    {
        std::string msg = "Alice: Hello Bob, how are you?";
        std::string cipher = AES_CBC_Encrypt(msg, key);
        std::string decrypted = AES_CBC_Decrypt(cipher, key);
        std::cout << "  Chat msg  : \"" << msg << "\"\n";
        std::cout << "  Cipher len: " << cipher.size() << " bytes\n";
        std::cout << "  Decrypted : \"" << decrypted << "\"\n";
        reportTest("Chat message format round trip", decrypted == msg);
    }
}

// ============================================================
//  TEST 6 — Different IVs produce different ciphertext
//  CBC mode should never produce identical ciphertext for
//  the same message encrypted twice (different IV each time)
// ============================================================
void testIVRandomness() {
    std::cout << CYAN << BOLD << "\n[6] IV Randomness (same message → different ciphertext)\n" << RESET;

    uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
    };

    std::string msg = "Hello Bob!";
    std::string cipher1 = AES_CBC_Encrypt(msg, key);
    std::string cipher2 = AES_CBC_Encrypt(msg, key);

    printHexStr("  Cipher 1  : ", cipher1);
    printHexStr("  Cipher 2  : ", cipher2);

    reportTest("Two encryptions of same message differ",
               cipher1 != cipher2);
}

// ============================================================
//  Main
// ============================================================
int main() {
    std::cout << BOLD << YELLOW
              << "╔══════════════════════════════════════════╗\n"
              << "║    AES-128 CBC Implementation Tests      ║\n"
              << "║    Validated against NIST FIPS-197       ║\n"
              << "╚══════════════════════════════════════════╝\n"
              << RESET;

    testGFMultiply();
    testKeyExpansion();
    testBlockEncrypt();
    testBlockDecrypt();
    testCBCRoundTrip();
    testIVRandomness();

    std::cout << "\n" << BOLD
              << "══════════════════════════════════════════\n"
              << "  Results: "
              << GREEN << passed << " passed" << RESET << BOLD << "  |  "
              << (failed > 0 ? RED : GREEN)
              << failed << " failed" << RESET << BOLD << "\n"
              << "══════════════════════════════════════════\n"
              << RESET;

    return failed == 0 ? 0 : 1;
}
