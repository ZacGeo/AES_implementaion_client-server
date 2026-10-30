#include <iostream>
#include <iomanip>
#include <cstring>
#include <string>
#include <cstdint>
#include "aes.hpp"

// ANSI colors
#define GREEN  "\033[1;32m"
#define RED    "\033[1;31m"
#define YELLOW "\033[1;33m"
#define CYAN   "\033[1;36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

// ============================================================
//  Global test counters
// ============================================================
static const int TOTAL_TESTS = 20;
int passed = 0;
int failed = 0;
int currentTest = 0;

// ============================================================
//  Helper functions
// ============================================================
void printHex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
        if (i + 1 != len)
            std::cout << " ";
    }
    std::cout << std::dec << "\n";
}

void printHexStr(const std::string& label, const std::string& data) {
    printHex(label,
             reinterpret_cast<const uint8_t*>(data.data()),
             data.size());
}

bool bytesEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    return std::memcmp(a, b, len) == 0;
}

void reportTest(const std::string& name, bool ok) {
    ++currentTest;

    std::cout << "  [TEST "
              << std::setw(2) << std::setfill('0') << currentTest
              << "/" << TOTAL_TESTS << "] ";

    if (ok) {
        std::cout << GREEN << "[PASS] " << RESET << name << "\n";
        ++passed;
    } else {
        std::cout << RED << "[FAIL] " << RESET << name << "\n";
        ++failed;
    }

    // Restore normal fill character for later output.
    std::cout << std::setfill(' ');
}

// Shared AES-128 key used by the tests.
const uint8_t TEST_KEY[16] = {
    0x2b,0x7e,0x15,0x16,
    0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88,
    0x09,0xcf,0x4f,0x3c
};

// Run one CBC encrypt/decrypt round-trip and report PASS/FAIL.
void runCBCRoundTrip(const std::string& testName,
                     const std::string& message,
                     bool showDetails = false) {
    std::string cipher = AES_CBC_Encrypt(message, TEST_KEY);
    std::string decrypted = AES_CBC_Decrypt(cipher, TEST_KEY);

    if (showDetails) {
        std::cout << "    Original length : " << message.size() << " bytes\n";
        std::cout << "    Cipher length   : " << cipher.size() << " bytes\n";
        printHexStr("    Ciphertext      : ", cipher);
        std::cout << "    Decrypted       : \"" << decrypted << "\"\n";
    }

    reportTest(testName, decrypted == message);
}

// ============================================================
//  TESTS 1-5 — GF(2^8) multiplication
// ============================================================
void testGFMultiply() {
    std::cout << CYAN << BOLD
              << "\n=== GF(2^8) MULTIPLICATION TESTS ===\n"
              << RESET;

    reportTest("gf_multiply(0x57, 0x83) == 0xc1",
               gf_multiply(0x57, 0x83) == 0xc1);

    reportTest("gf_multiply(0x02, 0x87) == 0x15",
               gf_multiply(0x02, 0x87) == 0x15);

    reportTest("gf_multiply(0x03, 0x87) == 0x92",
               gf_multiply(0x03, 0x87) == 0x92);

    reportTest("GF identity: 0x01 * 0xAB == 0xAB",
               gf_multiply(0x01, 0xAB) == 0xAB);

    reportTest("GF zero property: 0x57 * 0x00 == 0x00",
               gf_multiply(0x57, 0x00) == 0x00);
}

// ============================================================
//  TEST 6 — AES-128 Key Expansion
//  NIST FIPS-197 Appendix A.1
// ============================================================
void testKeyExpansion() {
    std::cout << CYAN << BOLD
              << "\n=== AES-128 KEY EXPANSION TEST ===\n"
              << RESET;

    uint32_t expandedKey[44];
    keyExpansion(TEST_KEY, expandedKey);

    // Correct full key schedule for key:
    // 2b7e151628aed2a6abf7158809cf4f3c
    const uint32_t expected[44] = {
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
        0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6
    };

    bool allMatch = true;
    int firstWrong = -1;

    for (int i = 0; i < 44; ++i) {
        if (expandedKey[i] != expected[i]) {
            allMatch = false;
            firstWrong = i;
            break;
        }
    }

    if (!allMatch) {
        std::cout << "    First mismatch at W" << std::setw(2)
                  << std::setfill('0') << firstWrong << std::setfill(' ') << "\n"
                  << "    Got      : 0x" << std::hex << std::setw(8)
                  << std::setfill('0') << expandedKey[firstWrong] << "\n"
                  << "    Expected : 0x" << std::setw(8)
                  << expected[firstWrong] << std::dec << std::setfill(' ') << "\n";
    } else {
        std::cout << "    All 44 expanded-key words match the NIST vector.\n";
        std::cout << "    Final round key: "
                  << std::hex << std::setfill('0')
                  << std::setw(8) << expandedKey[40] << " "
                  << std::setw(8) << expandedKey[41] << " "
                  << std::setw(8) << expandedKey[42] << " "
                  << std::setw(8) << expandedKey[43]
                  << std::dec << std::setfill(' ') << "\n";
    }

    reportTest("Key expansion: all 44 words match NIST FIPS-197", allMatch);
}

// ============================================================
//  TEST 7 — Full AES block encryption
// ============================================================
void testBlockEncrypt() {
    std::cout << CYAN << BOLD
              << "\n=== AES-128 BLOCK ENCRYPTION TEST ===\n"
              << RESET;

    uint8_t block[16] = {
        0x32,0x43,0xf6,0xa8,
        0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,
        0xe0,0x37,0x07,0x34
    };

    const uint8_t expected[16] = {
        0x39,0x25,0x84,0x1d,
        0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97,
        0x19,0x6a,0x0b,0x32
    };

    uint32_t expandedKey[44];
    keyExpansion(TEST_KEY, expandedKey);

    printHex("    Plaintext  : ", block, 16);
    AES_EncryptBlock(block, expandedKey);
    printHex("    Ciphertext : ", block, 16);
    printHex("    Expected   : ", expected, 16);

    reportTest("AES block encryption matches NIST vector",
               bytesEqual(block, expected, 16));
}

// ============================================================
//  TEST 8 — Full AES block decryption
// ============================================================
void testBlockDecrypt() {
    std::cout << CYAN << BOLD
              << "\n=== AES-128 BLOCK DECRYPTION TEST ===\n"
              << RESET;

    uint8_t block[16] = {
        0x39,0x25,0x84,0x1d,
        0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97,
        0x19,0x6a,0x0b,0x32
    };

    const uint8_t expected[16] = {
        0x32,0x43,0xf6,0xa8,
        0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,
        0xe0,0x37,0x07,0x34
    };

    uint32_t expandedKey[44];
    keyExpansion(TEST_KEY, expandedKey);

    printHex("    Ciphertext : ", block, 16);
    AES_DecryptBlock(block, expandedKey);
    printHex("    Plaintext  : ", block, 16);
    printHex("    Expected   : ", expected, 16);

    reportTest("AES block decryption restores NIST plaintext",
               bytesEqual(block, expected, 16));
}

// ============================================================
//  TESTS 9-19 — CBC round-trip tests
// ============================================================
void testCBCRoundTrips() {
    std::cout << CYAN << BOLD
              << "\n=== AES-128 CBC ROUND-TRIP TESTS ===\n"
              << RESET;

    // TEST 9
    runCBCRoundTrip(
        "CBC round trip: short message",
        "Hello Bob!",
        true
    );

    // TEST 10
    runCBCRoundTrip(
        "CBC round trip: exactly 16 bytes",
        "1234567890ABCDEF"
    );

    // TEST 11
    runCBCRoundTrip(
        "CBC round trip: multi-block message",
        "Alice: This is a longer message that spans multiple AES blocks!"
    );

    // TEST 12
    runCBCRoundTrip(
        "CBC round trip: single character",
        "A"
    );

    // TEST 13
    runCBCRoundTrip(
        "CBC round trip: chat message",
        "Alice: Hello Bob, how are you?",
        true
    );

    // TEST 14 - edge case
    runCBCRoundTrip(
        "CBC round trip: empty message",
        ""
    );

    // TEST 15 - one byte below the AES block size
    runCBCRoundTrip(
        "CBC round trip: 15-byte message",
        "1234567890ABCDE"
    );

    // TEST 16 - one byte above the AES block size
    runCBCRoundTrip(
        "CBC round trip: 17-byte message",
        "1234567890ABCDEFG"
    );

    // TEST 17 - one byte below two complete blocks
    runCBCRoundTrip(
        "CBC round trip: 31-byte message",
        "1234567890123456789012345678901"
    );

    // TEST 18 - exactly two complete blocks
    runCBCRoundTrip(
        "CBC round trip: 32-byte message",
        "12345678901234567890123456789012"
    );

    // TEST 19 - one byte above two complete blocks
    runCBCRoundTrip(
        "CBC round trip: 33-byte message",
        "123456789012345678901234567890123"
    );
}

// ============================================================
//  TEST 20 — CBC IV randomness
// ============================================================
void testIVRandomness() {
    std::cout << CYAN << BOLD
              << "\n=== CBC IV RANDOMNESS TEST ===\n"
              << RESET;

    const std::string message = "Hello Bob!";

    std::string cipher1 = AES_CBC_Encrypt(message, TEST_KEY);
    std::string cipher2 = AES_CBC_Encrypt(message, TEST_KEY);

    printHexStr("    Cipher 1 : ", cipher1);
    printHexStr("    Cipher 2 : ", cipher2);

    reportTest("CBC uses a different IV/ciphertext on repeated encryption",
               cipher1 != cipher2);
}

// ============================================================
//  Main
// ============================================================
int main() {
    std::cout << BOLD << YELLOW
              << "╔════════════════════════════════════════════════════╗\n"
              << "║          AES-128 CBC IMPLEMENTATION TESTS         ║\n"
              << "║                  20 TEST CASES                    ║\n"
              << "╚════════════════════════════════════════════════════╝\n"
              << RESET;

    testGFMultiply();      // Tests 1-5
    testKeyExpansion();    // Test 6
    testBlockEncrypt();    // Test 7
    testBlockDecrypt();    // Test 8
    testCBCRoundTrips();   // Tests 9-19
    testIVRandomness();    // Test 20

    std::cout << "\n" << BOLD
              << "════════════════════════════════════════════════════\n"
              << "                 FINAL TEST SUMMARY\n"
              << "════════════════════════════════════════════════════\n"
              << "  Total tests : " << currentTest << "/" << TOTAL_TESTS << "\n"
              << "  Passed      : " << GREEN << passed << RESET << BOLD << "\n"
              << "  Failed      : "
              << (failed == 0 ? GREEN : RED) << failed << RESET << BOLD << "\n"
              << "----------------------------------------------------\n";

    if (currentTest == TOTAL_TESTS && failed == 0) {
        std::cout << GREEN
                  << "  ALL 20 TESTS PASSED\n"
                  << RESET;
    } else if (currentTest != TOTAL_TESTS) {
        std::cout << RED
                  << "  ERROR: expected 20 tests, but " << currentTest
                  << " were executed.\n"
                  << RESET;
    } else {
        std::cout << RED
                  << "  SOME TESTS FAILED\n"
                  << RESET;
    }

    std::cout << BOLD
              << "════════════════════════════════════════════════════\n"
              << RESET;

    return (currentTest == TOTAL_TESTS && failed == 0) ? 0 : 1;
}
