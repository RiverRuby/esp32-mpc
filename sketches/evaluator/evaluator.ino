#include <WiFi.h>
#include "garbled_circuit.h"
#include "oblivious_transfer.h"

// Network configuration
const char* ssid = "ESP32_Network";
const char* password = "testpassword";
const int TCP_PORT = 5555;

// Button/lights config
const int BUTTON_PIN_ON = 16;
const int BUTTON_PIN_OFF = 14;
const int LED_PIN = 17;

WiFiClient client;
GarbledCircuit::Circuit circuit;

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
                
                // Select my wire label based on my input using OT
                GarbledCircuit::WireLabel myLabel = ObliviousTransfer::receiveWireLabel(client, b);
                
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
                    Serial.println(result ? "It's a match!\n" : "No match.\n");
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