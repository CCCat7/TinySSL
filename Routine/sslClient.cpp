#include "../SSL/SSL.h"

int main(int argc, char *argv[])
{
    SSL sslClient;
    size_t sockfd = sslClient.SSLClientInit("127.0.0.1", SYS_SHA, SYS_AES);
    sslClient.SSLClientAloha(sockfd);
    sslClient.SSLClientCertificate(sockfd, SYS_ELGAMAL);
    for( ; ; ) {
        sslClient.SSLClientRSASessionKeyExchange(sockfd);
        sslClient.SSLClientSecurityTransmission(sockfd);
    }
        
    close(sockfd);
    return 0;
}