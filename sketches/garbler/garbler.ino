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

WiFiServer tcpServer(TCP_PORT);
GarbledCircuit::Circuit circuit;

// ECC OT Constants
#define ECC_KEY_SIZE 32  // P-256 uses 32 byte keys
#define ECC_POINT_SIZE (2 * ECC_KEY_SIZE + 1)  // Uncompressed point format

// Helper function for ECC operations
class ECCHelper {
private:
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
        mbedtls_mpi_fill_random(&scalar, 32, mbedtls_ctr_drbg_random, &ctr_drbg);
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

// Implements sender's side of ECC-based Chou-Orlandi OT
void sendWireLabelsOT(WiFiClient& client, const GarbledCircuit::WireLabel& label0, const GarbledCircuit::WireLabel& label1) {
    static ECCHelper ecc;
    
    mbedtls_ecp_point A, B;
    mbedtls_mpi a, neg_a;
    mbedtls_ecp_point_init(&A);
    mbedtls_ecp_point_init(&B);
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&neg_a);

    Serial.println("Garbler ECP variables initialized");
    
    // Generate random a and compute A = aG
    ecc.generateRandomScalar(a);
    mbedtls_ecp_mul(ecc.getGroup(), &A, &a, &ecc.getGroup()->G, 
                    mbedtls_ctr_drbg_random, ecc.getRNG());
    
    Serial.println("Garbler A = aG computed");
    
    // Send A to receiver
    uint8_t A_buf[65];  // Explicitly use 65 bytes for clarity
    size_t olen;
    int ret = mbedtls_ecp_point_write_binary(ecc.getGroup(), &A, 
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, A_buf, sizeof(A_buf));
    if (ret != 0 || olen != 65) {
        Serial.println("Error encoding point");
        return;
    }
    client.write(A_buf, 65);

    Serial.println("Garbler sent A to evaluator");
    
    // Receive B
    uint8_t B_buf[ECC_POINT_SIZE];
    while (client.available() < ECC_POINT_SIZE) delay(10);
    client.readBytes(B_buf, ECC_POINT_SIZE);
    mbedtls_ecp_point_read_binary(ecc.getGroup(), &B, B_buf, ECC_POINT_SIZE);

    Serial.println("Garbler received B");
    
    // Compute k0 = H(B^a)
    mbedtls_ecp_point k0_point;
    mbedtls_ecp_point_init(&k0_point);
    ecc.pointMultiply(k0_point, a, B);
    
    uint8_t k0_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &k0_point,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, k0_buf, sizeof(k0_buf));

    Serial.println("Garbler computed B^a");
    
    // Hash the point to get the key
    uint8_t k0_key[32];
    mbedtls_sha256(k0_buf, olen, k0_key, 0);

    Serial.println("Garbler computed k0 = H(B^a)");
    
    // Compute k1 = H((B/A)^a) using mbedtls_ecp_muladd
    mbedtls_ecp_point k1_point;
    mbedtls_ecp_point_init(&k1_point);

    mbedtls_mpi one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_lset(&one, 1);
    
    // Compute -a
    mbedtls_mpi_lset(&neg_a, -1);
    mbedtls_mpi_mul_mpi(&neg_a, &neg_a, &a);
    
    // Use mbedtls_ecp_muladd to compute k1 = a * B + (-a) * A
    mbedtls_ecp_muladd(ecc.getGroup(), &k1_point, &one, &k0_point, &neg_a, &A);

    Serial.println("Garbler computed a*B - a*A");

    uint8_t k1_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &k1_point,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, k1_buf, sizeof(k1_buf));
    
    uint8_t k1_key[32];
    mbedtls_sha256(k1_buf, olen, k1_key, 0);

    Serial.println("Garbler computed k1 = H(a*B - a*A)");
    
    // Encrypt and send wire labels
    uint8_t e0[sizeof(GarbledCircuit::WireLabel)];
    uint8_t e1[sizeof(GarbledCircuit::WireLabel)];
    
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        e0[i] = ((uint8_t*)&label0)[i] ^ k0_key[i % 32];
        e1[i] = ((uint8_t*)&label1)[i] ^ k1_key[i % 32];
    }

    Serial.println("Garbler encrypted wire labels");
    
    client.write(e0, sizeof(e0));
    client.write(e1, sizeof(e1));

    Serial.println("Garbler sent labels to receiver");
    
    // Cleanup
    mbedtls_ecp_point_free(&A);
    mbedtls_ecp_point_free(&B);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&neg_a);
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&k0_point);
    mbedtls_ecp_point_free(&k1_point);
}

void setup() {
    Serial.begin(115200);
    pinMode(LED_PIN, OUTPUT);
    pinMode(BUTTON_PIN_ON, INPUT_PULLUP);
    pinMode(BUTTON_PIN_OFF, INPUT_PULLUP);
    digitalWrite(LED_PIN, LOW);
    
    // Initialize garbled circuit
    circuit.begin();
    
    // Create Access Point
    WiFi.softAP(ssid, password);
    Serial.print("AP IP address: ");
    Serial.println(WiFi.softAPIP());
    
    tcpServer.begin();
    Serial.println("Server started");

    // Single quick blink to show readiness
    digitalWrite(LED_PIN, HIGH);
    delay(200);
    digitalWrite(LED_PIN, LOW);
}

void loop() {
    WiFiClient client = tcpServer.available();
    static bool buttonHandled = false;
    
    if (client) {
        if (!buttonHandled) {
            // Wait for button press
            bool a = false;
            bool inputReceived = false;
            
            while (!inputReceived) {
                if (digitalRead(BUTTON_PIN_ON) == LOW) {
                    a = true;
                    inputReceived = true;
                    delay(50);
                }
                else if (digitalRead(BUTTON_PIN_OFF) == LOW) {
                    a = false;
                    inputReceived = true;
                    delay(50);
                }
                delay(10);
            }

            digitalWrite(LED_PIN, HIGH);
            buttonHandled = true;
            
            // Generate wire labels
            GarbledCircuit::WireLabel a0, a1, b0, b1;
            circuit.generateWireLabel(a0, false);
            circuit.generateWireLabel(a1, true);
            circuit.generateWireLabel(b0, false);
            circuit.generateWireLabel(b1, true);
            
            // Create garbled AND table
            GarbledCircuit::TableEntry table[GarbledCircuit::TABLE_SIZE];
            circuit.createGarbledANDTable(a0, a1, b0, b1, table);
            
            // Send my input's wire label
            const GarbledCircuit::WireLabel& myWireLabel = a ? a1 : a0;
            client.write(myWireLabel.key, GarbledCircuit::KEY_SIZE);
            
            // Send both wire labels for receiver's input
            sendWireLabelsOT(client, b0, b1);
            
            // Send garbled table
            for(int i = 0; i < GarbledCircuit::TABLE_SIZE; i++)  {
                client.write(table[i].encrypted, GarbledCircuit::ENCRYPTED_SIZE);
            }
        }

        while (!client.available()) {
            delay(100);
        }

        bool result = client.read() == 1;
        
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
        
        client.stop();
        buttonHandled = false;
    }
}