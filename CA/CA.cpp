#include "CA.h"

size_t CA::ID(0);

CA::CA(size_t version, size_t algorithm_CA, ULL param_CA, std::pair<ULL, ULL> publicKey_CA, 
       size_t major_ID, size_t algorithm_USER, ULL param_USER, std::pair<ULL, ULL> publicKey_USER)
{
    this->Certificate_CA.version = version;
    this->Certificate_CA.CA_ID = CA::ID++;
    this->Certificate_CA.algorithm_CA = algorithm_CA;
    this->Certificate_CA.param_CA = param_CA;
    this->Certificate_CA.publicKey_CA = publicKey_CA;
    this->Certificate_CA.notBefore = time(NULL);
    this->Certificate_CA.notAfter = this->Certificate_CA.notBefore + LIFETIME;
    this->Certificate_CA.major_ID = major_ID;
    this->Certificate_CA.algorithm_USER = algorithm_USER;
    this->Certificate_CA.param_USER = param_USER;
    this->Certificate_CA.publicKey_USER = publicKey_USER;
}

CA::~CA() {}

Certificate CA::getCertificate()
{
    return this->Certificate_CA;
}

