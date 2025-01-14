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

WiFiServer tcpServer(TCP_PORT);
GarbledCircuit::Circuit circuit;

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
            
            // Send both wire labels for receiver's input using OT
            ObliviousTransfer::sendWireLabels(client, b0, b1);
            
            // Send garbled table
            for(int i = 0; i < GarbledCircuit::TABLE_SIZE; i++)  {
                client.write(table[i].encrypted, GarbledCircuit::ENCRYPTED_SIZE);
            }
        }

        while (!client.available()) {
            delay(100);
        }

        bool result = client.read() == 1;
        Serial.println(result ? "It's a match!" : "No match");
        
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