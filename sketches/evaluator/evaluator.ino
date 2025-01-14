#include <WiFi.h>
#include "garbled_circuit.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "esp_system.h"
#include "esp_heap_caps.h"

// Network configuration
const char* ssid = "ESP32_Network";
const char* password = "testpassword";
const int TCP_PORT = 5555;

// Button/lights config
const int BUTTON_PIN_ON = 16;
const int BUTTON_PIN_OFF = 14;
const int LED_PIN = 17;

// ECC OT Constants
#define ECC_KEY_SIZE 32  // P-256 uses 32 byte keys
#define ECC_POINT_SIZE (2 * ECC_KEY_SIZE + 1)  // Uncompressed point format

// Helper class (same as garbler.ino)
class ECCHelper {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group group;
    
public:
    ECCHelper() {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ecp_group_init(&group);
        
        // Initialize RNG
        mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
        
        // Load P-256 curve with hardware acceleration
        mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    }
    
    ~ECCHelper() {
        mbedtls_ecp_group_free(&group);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
    
    // Generate random scalar
    void generateRandomScalar(mbedtls_mpi& scalar) {
        // Initialize scalar to 0
        mbedtls_mpi_lset(&scalar, 0);
        
        // Generate random bytes for the scalar
        unsigned char buf[32];
        mbedtls_ctr_drbg_random(&ctr_drbg, buf, sizeof(buf));
        
        // Import random bytes into MPI
        mbedtls_mpi_read_binary(&scalar, buf, sizeof(buf));
        
        // Reduce modulo the curve order
        mbedtls_mpi_mod_mpi(&scalar, &scalar, &group.N);
    }
    
    // Point multiplication with hardware acceleration
    void pointMultiply(mbedtls_ecp_point& result, const mbedtls_mpi& scalar, 
                      const mbedtls_ecp_point& point) {
        mbedtls_ecp_mul(&group, &result, &scalar, &point, 
                        mbedtls_ctr_drbg_random, &ctr_drbg);
    }
    
    mbedtls_ecp_group* getGroup() { return &group; }
    mbedtls_ctr_drbg_context* getRNG() { return &ctr_drbg; }
};

WiFiClient client;
GarbledCircuit::Circuit circuit;

// Implements receiver's side of ECC-based Chou-Orlandi OT
GarbledCircuit::WireLabel receiveWireLabelOT(WiFiClient& client, bool choice) {
    static ECCHelper ecc;
    
    mbedtls_ecp_point A, B;
    mbedtls_mpi b;
    mbedtls_ecp_point_init(&A);
    mbedtls_ecp_point_init(&B);
    mbedtls_mpi_init(&b);
    
    Serial.println("Evaluator ECP variables initialized");
    
    // Receive A from sender
    uint8_t A_buf[ECC_POINT_SIZE];
    while (client.available() < ECC_POINT_SIZE) {
      Serial.println(client.available());
      delay(1000);
    }
    client.readBytes(A_buf, ECC_POINT_SIZE);
    
    Serial.print("Evaluator received A point: ");
    for(int i = 0; i < ECC_POINT_SIZE; i++) {
        Serial.printf("%02X ", A_buf[i]);
    }
    Serial.println();

    mbedtls_ecp_point_read_binary(ecc.getGroup(), &A, A_buf, ECC_POINT_SIZE);
    
    // Generate random b and debug output
    ecc.generateRandomScalar(b);
    uint8_t b_bytes[32];
    mbedtls_mpi_write_binary(&b, (unsigned char*)b_bytes, sizeof(b_bytes));
    Serial.print("Evaluator scalar b: ");
    for(int i = 0; i < 32; i++) {
        Serial.printf("%02X ", b_bytes[i]);
    }
    Serial.println();
    
    // Compute g^b
    mbedtls_ecp_point temp;
    mbedtls_ecp_point_init(&temp);
    mbedtls_ecp_mul(ecc.getGroup(), &temp, &b, &ecc.getGroup()->G, 
                    mbedtls_ctr_drbg_random, ecc.getRNG());

    // Debug output for g^b
    uint8_t gb_buf[ECC_POINT_SIZE];
    size_t olen;
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &temp,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, gb_buf, sizeof(gb_buf));
    Serial.print("Evaluator g^b point: ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", gb_buf[i]);
    }
    Serial.println();
    
    if (choice) {
        // B = A + g^b using muladd: B = 1*A + 1*g^b
        mbedtls_mpi one;
        mbedtls_mpi_init(&one);
        mbedtls_mpi_lset(&one, 1);
        
        mbedtls_ecp_muladd(ecc.getGroup(), &B, &one, &A, &one, &temp);

        Serial.println("Evaluator computed B = A + g^b");
        
        mbedtls_mpi_free(&one);
    } else {
        // B = g^b
        mbedtls_ecp_copy(&B, &temp);

        Serial.println("Evaluator computed B = g^b");
    }
    
    Serial.println("Evaluator computed B");
    
    // Send B to sender
    uint8_t B_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &B,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, B_buf, sizeof(B_buf));
    
    Serial.print("Evaluator sending B point: ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", B_buf[i]);
    }
    Serial.println();
    
    client.write(B_buf, ECC_POINT_SIZE);
    
    // Compute k = A^b
    mbedtls_ecp_point k_point;
    mbedtls_ecp_point_init(&k_point);
    ecc.pointMultiply(k_point, b, A);
    
    uint8_t k_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &k_point,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, k_buf, sizeof(k_buf));
    
    Serial.print("Evaluator k point (A^b): ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", k_buf[i]);
    }
    Serial.println();
    
    uint8_t key[32];
    mbedtls_sha256(k_buf, olen, key, 0);
    
    Serial.print("Evaluator derived key: ");
    for(int i = 0; i < 32; i++) {
        Serial.printf("%02X ", key[i]);
    }
    Serial.println();
    
    // Receive encrypted wire labels
    uint8_t e0[sizeof(GarbledCircuit::WireLabel)];
    uint8_t e1[sizeof(GarbledCircuit::WireLabel)];
    while (client.available() < sizeof(e0) + sizeof(e1)) delay(10);
    client.readBytes(e0, sizeof(e0));
    client.readBytes(e1, sizeof(e1));
    
    Serial.print("Evaluator received e0: ");
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        Serial.printf("%02X ", e0[i]);
    }
    Serial.println();
    
    Serial.print("Evaluator received e1: ");
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        Serial.printf("%02X ", e1[i]);
    }
    Serial.println();
    
    // Decrypt chosen wire label
    GarbledCircuit::WireLabel result;
    uint8_t* encrypted = choice ? e1 : e0;
    
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        ((uint8_t*)&result)[i] = encrypted[i] ^ key[i % 32];
    }
    
    Serial.print("Evaluator decrypted label: ");
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        Serial.printf("%02X ", ((uint8_t*)&result)[i]);
    }
    Serial.println();
    
    // Cleanup
    mbedtls_ecp_point_free(&A);
    mbedtls_ecp_point_free(&B);
    mbedtls_mpi_free(&b);
    mbedtls_ecp_point_free(&k_point);
    mbedtls_ecp_point_free(&temp);
    
    return result;
}

void setup() {
    Serial.begin(115200);
    pinMode(LED_PIN, OUTPUT);
    pinMode(BUTTON_PIN_ON, INPUT_PULLUP);
    pinMode(BUTTON_PIN_OFF, INPUT_PULLUP);
    digitalWrite(LED_PIN, LOW);
    
    // Initialize garbled circuit
    circuit.begin();
    
    Serial.println("Connecting to AP...");
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nConnected to AP");

    // Single quick blink to show readiness
    digitalWrite(LED_PIN, HIGH);
    delay(200);
    digitalWrite(LED_PIN, LOW);
}

void loop() {
    static bool buttonHandled = false;
    
    if (!client.connected()) {
        if (client.connect(WiFi.gatewayIP(), TCP_PORT)) {
            if (!buttonHandled) {
                // Wait for button press
                bool b = false;
                bool inputReceived = false;
                
                while (!inputReceived) {
                    if (digitalRead(BUTTON_PIN_ON) == LOW) {
                        b = true;
                        inputReceived = true;
                        delay(50);
                    }
                    else if (digitalRead(BUTTON_PIN_OFF) == LOW) {
                        b = false;
                        inputReceived = true;
                        delay(50);
                    }
                    delay(10);
                }
                
                digitalWrite(LED_PIN, HIGH);
                buttonHandled = true;
                
                // Receive sender's wire label
                GarbledCircuit::WireLabel senderLabel;
                while (client.available() < GarbledCircuit::KEY_SIZE) delay(10);
                client.readBytes(senderLabel.key, GarbledCircuit::KEY_SIZE);
                
                // Select my wire label based on my input
                GarbledCircuit::WireLabel myLabel = receiveWireLabelOT(client, b);
                
                // Receive garbled table
                GarbledCircuit::TableEntry table[GarbledCircuit::TABLE_SIZE];
                for(int i = 0; i < GarbledCircuit::TABLE_SIZE; i++) {
                    while (client.available() < GarbledCircuit::ENCRYPTED_SIZE) delay(10);
                    client.readBytes(table[i].encrypted, GarbledCircuit::ENCRYPTED_SIZE);
                }
                
                // Try to decrypt each table entry
                bool result = false;
                bool decrypted = false;
                
                Serial.println("Evaluator attempting to decrypt table entries");
                
                for(int i = 0; i < GarbledCircuit::TABLE_SIZE; i++) {
                    if(circuit.decryptEntry(senderLabel, myLabel, table[i], result)) {
                        decrypted = true;
                        break;
                    }
                }
                
                if (decrypted) {
                    Serial.println("Evaluator successfully decrypted result");
                    Serial.println(result ? "It's a match!" : "No match.")
                    client.write(result ? 1 : 0);
                    
                    if (result) {
                        // Blink for 5 seconds then stay on
                        for(int i = 0; i < 25; i++) {
                            digitalWrite(LED_PIN, HIGH);
                            delay(100);
                            digitalWrite(LED_PIN, LOW);
                            delay(100);
                        }
                    } else {
                        // Single quick blink
                        digitalWrite(LED_PIN, HIGH);
                        delay(200);
                        digitalWrite(LED_PIN, LOW);
                    }
                } else {
                    Serial.println("Evaluator failed to decrypt any table entries");
                    client.write((uint8_t)0);
                    // Error pattern - three quick blinks
                    for(int i = 0; i < 3; i++) {
                        digitalWrite(LED_PIN, HIGH);
                        delay(100);
                        digitalWrite(LED_PIN, LOW);
                        delay(100);
                    }
                }
            }
            buttonHandled = false;
        }
        delay(1000);
    }
}