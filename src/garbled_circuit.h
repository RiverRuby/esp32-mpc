#ifndef GARBLED_CIRCUIT_H
#define GARBLED_CIRCUIT_H

#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <Arduino.h>

namespace GarbledCircuit {

// Crypto constants
const int KEY_SIZE = 16;       // 128-bit keys
const int TABLE_SIZE = 4;      // 2^2 entries for AND gate
const int ENTRY_SIZE = 32;     // Two AES blocks
const int ENCRYPTED_SIZE = ENTRY_SIZE + 32;  // Add space for two IVs

struct TableEntry {
    uint8_t encrypted[ENCRYPTED_SIZE];  // Space for two IVs plus encrypted data
};

struct WireLabel {
    uint8_t key[KEY_SIZE];
    bool permute_bit;
};

class Circuit {
public:
    Circuit();
    ~Circuit();
    
    // Initialize the circuit with entropy for random number generation
    void begin();
    
    // Sender-side functions
    void generateWireLabel(WireLabel& label, bool permute);
    void encryptEntry(const WireLabel& wa, const WireLabel& wb, TableEntry& entry, bool result);
    void createGarbledANDTable(const WireLabel& a0, const WireLabel& a1, 
                              const WireLabel& b0, const WireLabel& b1, 
                              TableEntry* table);
    
    // Receiver-side functions
    bool decryptEntry(const WireLabel& wa, const WireLabel& wb, 
                     const TableEntry& entry, bool& result);
    
    // Utility functions
    void printWireLabel(const char* prefix, const WireLabel& label);
    void printTableEntry(const char* prefix, const TableEntry& entry);

private:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool initialized;
};

} // namespace GarbledCircuit

#endif // GARBLED_CIRCUIT_H