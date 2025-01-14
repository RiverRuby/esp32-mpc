#include "oblivious_transfer.h"
#include "mbedtls/sha256.h"

void ObliviousTransfer::sendWireLabels(WiFiClient& client, 
                                      const GarbledCircuit::WireLabel& label0, 
                                      const GarbledCircuit::WireLabel& label1) {
    ECCHelper ecc;
    
    mbedtls_ecp_point A, B;
    mbedtls_mpi a;
    mbedtls_ecp_point_init(&A);
    mbedtls_ecp_point_init(&B);
    mbedtls_mpi_init(&a);

    Serial.println("Garbler ECP variables initialized");
    
    // Generate random a and compute A = aG
    ecc.generateRandomScalar(a);
    mbedtls_ecp_mul(ecc.getGroup(), &A, &a, &ecc.getGroup()->G, 
                    mbedtls_ctr_drbg_random, ecc.getRNG());
    
    // Debug output for 'a'
    Serial.print("Garbler scalar a: ");
    uint8_t a_bytes[32];
    mbedtls_mpi_write_binary(&a, (unsigned char*)a_bytes, sizeof(a_bytes));
    for(int i = 0; i < 32; i++) {
        Serial.printf("%02X ", a_bytes[i]);
    }
    Serial.println();
    
    // Send A to receiver and debug output
    uint8_t A_buf[ECC_POINT_SIZE];
    size_t olen;
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &A, 
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, A_buf, sizeof(A_buf));
    Serial.print("Garbler sending A point: ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", A_buf[i]);
    }
    Serial.println();
    
    client.write(A_buf, ECC_POINT_SIZE);

    // Receive and debug output B
    uint8_t B_buf[ECC_POINT_SIZE];
    while (client.available() < ECC_POINT_SIZE) delay(10);
    client.readBytes(B_buf, ECC_POINT_SIZE);
    Serial.print("Garbler received B point: ");
    for(int i = 0; i < ECC_POINT_SIZE; i++) {
        Serial.printf("%02X ", B_buf[i]);
    }
    Serial.println();
    
    mbedtls_ecp_point_read_binary(ecc.getGroup(), &B, B_buf, ECC_POINT_SIZE);
    
    // Compute k0 = B^a
    uint8_t k0_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point k0_point;
    mbedtls_ecp_point_init(&k0_point);
    ecc.pointMultiply(k0_point, a, B);
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &k0_point,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, k0_buf, sizeof(k0_buf));
    
    Serial.print("Garbler k0 point (B^a): ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", k0_buf[i]);
    }
    Serial.println();
    
    // Hash k0
    uint8_t k0_key[32];
    mbedtls_sha256(k0_buf, olen, k0_key, 0);
    Serial.print("Garbler k0 key: ");
    for(int i = 0; i < 32; i++) {
        Serial.printf("%02X ", k0_key[i]);
    }
    Serial.println();
    
    // Compute k1 = (B-A)^a
    mbedtls_ecp_point k1_point, temp_point;
    mbedtls_ecp_point_init(&k1_point);
    mbedtls_ecp_point_init(&temp_point);

    mbedtls_mpi one, neg_one;
    mbedtls_mpi_init(&one);
    mbedtls_mpi_init(&neg_one);
    mbedtls_mpi_lset(&one, 1);
    mbedtls_mpi_copy(&neg_one, &one);
    mbedtls_mpi_sub_mpi(&neg_one, &ecc.getGroup()->N, &neg_one);  // neg_one = N - 1
    
    // Compute B - A
    mbedtls_ecp_muladd(ecc.getGroup(), &temp_point, &one, &B, &neg_one, &A);

    // Compute a * (B - A)
    ecc.pointMultiply(k1_point, a, temp_point);

    uint8_t k1_buf[ECC_POINT_SIZE];
    mbedtls_ecp_point_write_binary(ecc.getGroup(), &k1_point,
                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
                                  &olen, k1_buf, sizeof(k1_buf));
    
    Serial.print("Garbler k1 point (B-A)*a: ");
    for(size_t i = 0; i < olen; i++) {
        Serial.printf("%02X ", k1_buf[i]);
    }
    Serial.println();
    
    // Hash k1
    uint8_t k1_key[32];
    mbedtls_sha256(k1_buf, olen, k1_key, 0);
    Serial.print("Garbler k1 key: ");
    for(int i = 0; i < 32; i++) {
        Serial.printf("%02X ", k1_key[i]);
    }
    Serial.println();
    
    // Encrypt wire labels
    uint8_t e0[sizeof(GarbledCircuit::WireLabel)];
    uint8_t e1[sizeof(GarbledCircuit::WireLabel)];
    
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        e0[i] = ((uint8_t*)&label0)[i] ^ k0_key[i % 32];
        e1[i] = ((uint8_t*)&label1)[i] ^ k1_key[i % 32];
    }
    
    Serial.print("Garbler encrypted label 0: ");
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        Serial.printf("%02X ", e0[i]);
    }
    Serial.println();
    
    Serial.print("Garbler encrypted label 1: ");
    for(size_t i = 0; i < sizeof(GarbledCircuit::WireLabel); i++) {
        Serial.printf("%02X ", e1[i]);
    }
    Serial.println();
    
    client.write(e0, sizeof(e0));
    client.write(e1, sizeof(e1));

    // Cleanup
    mbedtls_ecp_point_free(&A);
    mbedtls_ecp_point_free(&B);
    mbedtls_ecp_point_free(&temp_point);
    mbedtls_mpi_free(&a);
    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&neg_one);
    mbedtls_ecp_point_free(&k0_point);
    mbedtls_ecp_point_free(&k1_point);
}

GarbledCircuit::WireLabel ObliviousTransfer::receiveWireLabel(WiFiClient& client, bool choice) {
    ECCHelper ecc;
    
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