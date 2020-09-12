#include "../SSL/SSL.h"

int main(int argc, char *argv[])
{
    SSL sslServer;
    size_t listenfd = sslServer.SSLServerInit(SYS_SHA, SYS_AES);
    size_t connfd = sslServer.SSLServerAloha(listenfd);
    sslServer.SSLServerCertificate(connfd, SYS_ELGAMAL);
    for( ; ; ) {
        sslServer.SSLServerRSASessionKeyExchange(connfd);
        sslServer.SSLServerSecurityTransmission(connfd);
    }
        
    close(connfd);
    return 0;
}