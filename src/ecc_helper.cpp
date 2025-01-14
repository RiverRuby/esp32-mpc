#include "ecc_helper.h"

ECCHelper::ECCHelper() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecp_group_init(&group);
    
    // Initialize RNG
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    
    // Load P-256 curve with hardware acceleration
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
}

ECCHelper::~ECCHelper() {
    mbedtls_ecp_group_free(&group);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

void ECCHelper::generateRandomScalar(mbedtls_mpi& scalar) {
    mbedtls_mpi_lset(&scalar, 0);
    unsigned char buf[32];
    mbedtls_ctr_drbg_random(&ctr_drbg, buf, sizeof(buf));
    mbedtls_mpi_read_binary(&scalar, buf, sizeof(buf));
    mbedtls_mpi_mod_mpi(&scalar, &scalar, &group.N);
}

void ECCHelper::pointMultiply(mbedtls_ecp_point& result, const mbedtls_mpi& scalar, 
                            const mbedtls_ecp_point& point) {
    mbedtls_ecp_mul(&group, &result, &scalar, &point, 
                    mbedtls_ctr_drbg_random, &ctr_drbg);
} 