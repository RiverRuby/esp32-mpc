#ifndef OBLIVIOUS_TRANSFER_H
#define OBLIVIOUS_TRANSFER_H

#include <WiFiClient.h>
#include "garbled_circuit.h"
#include "ecc_helper.h"

#define ECC_KEY_SIZE 32
#define ECC_POINT_SIZE (2 * ECC_KEY_SIZE + 1)

class ObliviousTransfer {
public:
    // Sender's side of ECC-based Chou-Orlandi OT
    static void sendWireLabels(WiFiClient& client, 
                             const GarbledCircuit::WireLabel& label0, 
                             const GarbledCircuit::WireLabel& label1);
    
    // Receiver's side of ECC-based Chou-Orlandi OT
    static GarbledCircuit::WireLabel receiveWireLabel(WiFiClient& client, bool choice);
};

#endif 