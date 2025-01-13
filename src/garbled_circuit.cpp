#include "garbled_circuit.h"

namespace GarbledCircuit {

Circuit::Circuit() : initialized(false) {}

Circuit::~Circuit() {
    if (initialized) {
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
}

void Circuit::begin() {
    if (!initialized) {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
        initialized = true;
    }
}

void Circuit::generateWireLabel(WireLabel& label, bool permute) {
    mbedtls_ctr_drbg_random(&ctr_drbg, label.key, KEY_SIZE);
    label.permute_bit = permute;
}

void Circuit::encryptEntry(const WireLabel& wa, const WireLabel& wb, TableEntry& entry, bool result) {
    mbedtls_aes_context aes;
    uint8_t iv1[16], iv2[16];
    uint8_t plaintext[ENTRY_SIZE] = {0};  // Initialize all to zero
    uint8_t temp[ENTRY_SIZE];
    uint8_t final_cipher[ENTRY_SIZE];
    
    // Generate random IVs
    mbedtls_ctr_drbg_random(&ctr_drbg, iv1, 16);
    mbedtls_ctr_drbg_random(&ctr_drbg, iv2, 16);
    memcpy(entry.encrypted, iv1, 16);
    memcpy(entry.encrypted + 16, iv2, 16);
    
    // Set result in plaintext
    plaintext[0] = result ? 1 : 0;
    
    mbedtls_aes_init(&aes);
    
    // First encryption with wa's key
    if(mbedtls_aes_setkey_enc(&aes, wa.key, 128) != 0) {
        Serial.println("Failed to set encryption key A");
        return;
    }
    
    if(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, ENTRY_SIZE, iv1, plaintext, temp) != 0) {
        Serial.println("First encryption failed");
        return;
    }
    
    // Second encryption with wb's key
    if(mbedtls_aes_setkey_enc(&aes, wb.key, 128) != 0) {
        Serial.println("Failed to set encryption key B");
        return;
    }
    
    if(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, ENTRY_SIZE, iv2, temp, final_cipher) != 0) {
        Serial.println("Second encryption failed");
        return;
    }
    
    // Store ciphertext
    memcpy(entry.encrypted + 32, final_cipher, ENTRY_SIZE);
    
    mbedtls_aes_free(&aes);
}

void Circuit::createGarbledANDTable(const WireLabel& a0, const WireLabel& a1, 
                                  const WireLabel& b0, const WireLabel& b1, 
                                  TableEntry* table) {
    for(int i = 0; i < 2; i++) {
        for(int j = 0; j < 2; j++) {
            const WireLabel& wa = (i == 0) ? a0 : a1;
            const WireLabel& wb = (j == 0) ? b0 : b1;
            bool result = i && j;  // AND truth table
            encryptEntry(wa, wb, table[2*i + j], result);
        }
    }
}

bool Circuit::decryptEntry(const WireLabel& wa, const WireLabel& wb, 
                         const TableEntry& entry, bool& result) {
    mbedtls_aes_context aes;
    uint8_t iv1[16], iv2[16];
    uint8_t temp[ENTRY_SIZE];
    uint8_t plaintext[ENTRY_SIZE];
    uint8_t encrypted[ENTRY_SIZE];
    
    memcpy(iv1, entry.encrypted, 16);
    memcpy(iv2, entry.encrypted + 16, 16);
    memcpy(encrypted, entry.encrypted + 32, ENTRY_SIZE);
    
    mbedtls_aes_init(&aes);
    
    // First decryption with wb's key
    if(mbedtls_aes_setkey_dec(&aes, wb.key, 128) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    
    if(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ENTRY_SIZE, iv2, encrypted, temp) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    
    // Second decryption with wa's key
    if(mbedtls_aes_setkey_dec(&aes, wa.key, 128) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    
    if(mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ENTRY_SIZE, iv1, temp, plaintext) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    
    mbedtls_aes_free(&aes);

    // Check if all bytes after the first are zero
    for (int i = 1; i < ENTRY_SIZE; i++) {
        if (plaintext[i] != 0) {
            return false;
        }
    }
    
    result = (plaintext[0] == 1);
    return true;
}

void Circuit::printWireLabel(const char* prefix, const WireLabel& label) {
    Serial.print(prefix);
    Serial.print(" Key: ");
    for(int i = 0; i < KEY_SIZE; i++) {
        Serial.printf("%02X ", label.key[i]);
    }
    Serial.println();
}

void Circuit::printTableEntry(const char* prefix, const TableEntry& entry) {
    Serial.print(prefix);
    Serial.print(" Entry: ");
    for(int i = 0; i < ENCRYPTED_SIZE; i++) {
        Serial.printf("%02X ", entry.encrypted[i]);
        if (i == 15 || i == 31) Serial.print("- ");
    }
    Serial.println();
}

} // namespace GarbledCircuit