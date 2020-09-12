#include <iostream>
#include <sys/types.h>
#include <cstdlib>
#include <algorithm>
#include <bitset>
#include <time.h>

typedef std::bitset<8> byte;
typedef unsigned long long ULL;

#define X509_V1 1
#define X509_V3 2
#define SYS_RSA 3
#define SYS_ELGAMAL 4

#define LIFETIME 3600 //1 hour

struct Certificate {
    size_t version;
    size_t CA_ID;
    size_t algorithm_CA;
    ULL param_CA;
    std::pair<ULL, ULL> publicKey_CA;
    time_t notBefore;
    time_t notAfter;
    size_t major_ID;
    size_t algorithm_USER;
    ULL param_USER;
    std::pair<ULL, ULL> publicKey_USER;
};

class CA
{
private:
    Certificate Certificate_CA;
    static size_t ID;
public:
    CA(size_t version, size_t algorithm_CA, ULL param_CA, std::pair<ULL, ULL> publicKey_CA, 
       size_t major_ID, size_t algorithm_USER, ULL params_USER, std::pair<ULL, ULL> publicKey_USER);
    ~CA();
    Certificate getCertificate();
};

