#include <iostream>
#include <sys/types.h>
#include <cstdlib>
#include <algorithm>
#include <bitset>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include "../CA/CA.h"
#include "../RC4/RC4.h"
#include "../AES/AES.h"
#include "../RSA/RSA.h"
#include "../SHA/SHA.h"

#define SYS_RC4 5
#define SYS_DES 6
#define SYS_AES 7
#define SYS_3DES 8
#define SYS_MD5 9
#define SYS_SHA 10
#define SSLVERSION 11

#define MAXMSGLEN 4096
#define FRAGMSGSIZE 1424    /* 16 * 89 */
#define ABSTRACTLEN 64   /* total = 1424 + 64 = 1488 */

struct clientAloha {
    size_t version;
    time_t timeStamp;
    size_t sessionId;
    size_t clientAbstractAlgorithm;
    size_t clientEncryptAlgorithm;
};

struct serverAloha {
    size_t version;
    time_t timeStamp;
    size_t sessionId;
    size_t serverAbstractAlgorithm;
    size_t serverEncryptAlgorithm;
};

class SSL
{
private:
    clientAloha clientAlohaMsg;
    serverAloha serverAlohaMsg;
    size_t clientMajorId, serverMajorId;
    static size_t sessionId;
    Certificate clientCertificate;
    Certificate serverCertificate;
    std::pair<ULL, ULL> publicKey_CA;
    std::pair<ULL, ULL> privateKey_CA;    
    std::pair<ULL, ULL> publicKey_Client;
    std::pair<ULL, ULL> privateKey_Client;
    std::pair<ULL, ULL> publicKey_Server;
    std::pair<ULL, ULL> privateKey_Server;
    byte *sessionKey;
public:
    SSL();
    ~SSL();
    size_t SSLClientInit(const char *serverIP, size_t abstractAlgorithm, size_t encryptAlogorithm);
    size_t SSLServerInit(size_t abstractAlgorithm, size_t encryptAlogorithm);
    void SSLClientAloha(size_t sockfd);
    size_t SSLServerAloha(size_t listenfd);
    size_t SSLServerCertificate(size_t connfd, size_t method);
    size_t SSLClientCertificate(size_t sockfd, size_t method);
    size_t SSLClientRSASessionKeyExchange(size_t sockfd);
    size_t SSLServerRSASessionKeyExchange(size_t connfd);
    void SSLClientSecurityTransmission(size_t sockfd);
    void SSLServerSecurityTransmission(size_t connfd);
};

