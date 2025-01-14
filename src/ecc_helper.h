#ifndef ECC_HELPER_H
#define ECC_HELPER_H

#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

class ECCHelper {
private:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecp_group group;
    
public:
    ECCHelper();
    ~ECCHelper();
    
    void generateRandomScalar(mbedtls_mpi& scalar);
    void pointMultiply(mbedtls_ecp_point& result, const mbedtls_mpi& scalar, 
                      const mbedtls_ecp_point& point);
    
    mbedtls_ecp_group* getGroup() { return &group; }
    mbedtls_ctr_drbg_context* getRNG() { return &ctr_drbg; }
};

#endif 