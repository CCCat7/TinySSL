#include "SSL.h"

size_t SSL::sessionId(0);

SSL::SSL():serverMajorId(1), clientMajorId(2){}

SSL::~SSL(){}

//socket prepare: do socket(), connect(), then return the sockfd in order to send/recv etc. (client)
size_t SSL::SSLClientInit(const char *serverIP, size_t abstractAlgorithm, size_t encryptAlogorithm)
{
    this->clientAlohaMsg.version = SSLVERSION;
    this->clientAlohaMsg.sessionId = SSL::sessionId;
    this->clientAlohaMsg.timeStamp = time(NULL);
    this->clientAlohaMsg.clientAbstractAlgorithm = abstractAlgorithm;
    this->clientAlohaMsg.clientEncryptAlgorithm = encryptAlogorithm;

    size_t sockfd; 
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {   
        std::cout << "Failed to create socket." << std::endl;
        exit(0);
    }

    struct sockaddr_in severAddress;    
    memset(&severAddress, 0, sizeof(severAddress)); 
    severAddress.sin_family = AF_INET;
    severAddress.sin_port = htons(6666);  

    if(inet_pton(AF_INET, serverIP, &severAddress.sin_addr) <= 0) {
        printf("inet_pton error for %s\n", serverIP);
        exit(0);
    }

    if(connect(sockfd, (struct sockaddr*)&severAddress, sizeof(severAddress)) < 0){
        std::cout << "Failed to connect to the server." << std::endl;
        exit(0);
    }

    return sockfd;
}

//socket prepare: do socket(), bind(), listen(), then return the listenfd in order to do accept() etc. (server)
size_t SSL::SSLServerInit(size_t abstractAlgorithm, size_t encryptAlogorithm)
{
    this->serverAlohaMsg.version = SSLVERSION;
    this->serverAlohaMsg.sessionId = SSL::sessionId;
    this->serverAlohaMsg.timeStamp = time(NULL);
    this->serverAlohaMsg.serverAbstractAlgorithm = abstractAlgorithm;
    this->serverAlohaMsg.serverEncryptAlgorithm = encryptAlogorithm;

    struct sockaddr_in servAddress;
    size_t listenfd;

    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("create socket error: ");
        exit(0);
    }

    memset(&servAddress, 0, sizeof(servAddress));
    servAddress.sin_family = AF_INET;
    servAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddress.sin_port = htons(6666);

    if(bind(listenfd, (struct sockaddr*)&servAddress, sizeof(servAddress)) == -1) {
        perror("bind socket error: ");
        exit(0);
    }

    if(listen(listenfd, 10) == -1) {
        perror("listen socket error: ");
        exit(0);
    }

    return listenfd;
}

//handshake phase 1: hello exchange (client)
void SSL::SSLClientAloha(size_t sockfd)
{
    char alohaSendBuf[MAXMSGLEN];
    memcpy(alohaSendBuf, &this->clientAlohaMsg, sizeof(clientAloha));
    if(send(sockfd, alohaSendBuf, sizeof(alohaSendBuf), 0) < 0){
        perror("send msg error: ");
        exit(0);
    }

    char alohaRecvBuf[MAXMSGLEN];
    recv(sockfd, alohaRecvBuf, sizeof(alohaRecvBuf), 0);
    serverAloha *alohaMsgRecv = (serverAloha *)alohaRecvBuf;

    if((this->clientAlohaMsg.clientAbstractAlgorithm == alohaMsgRecv->serverAbstractAlgorithm) && (this->clientAlohaMsg.clientEncryptAlgorithm == alohaMsgRecv->serverEncryptAlgorithm)) {
        ;
    }
    else {
        if(this->clientAlohaMsg.clientAbstractAlgorithm == alohaMsgRecv->serverAbstractAlgorithm)
            std::cout << "Encrypt algorithm disaccord." << std::endl;
        else if(this->clientAlohaMsg.clientEncryptAlgorithm == alohaMsgRecv->serverEncryptAlgorithm)
            std::cout << "Abstract algorithm disaccord." << std::endl;
        else
            std::cout << "Abstract algorithm and Encrypt algorithm disaccord." << std::endl;
        close(sockfd);
        SSL::sessionId++;
        exit(0);
    }
} 

//handshake phase 1: hello exchange (server)
size_t SSL::SSLServerAloha(size_t listenfd)
{
    size_t connfd;
    for( ; ; ) {
        if((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1) {
            perror("accept socket error: ");
            continue;
        }

        char alohaRecvBuf[MAXMSGLEN];
        recv(connfd, alohaRecvBuf, sizeof(alohaRecvBuf), 0);
        clientAloha *alohaMsgRecv = (clientAloha *)alohaRecvBuf;

        char alohaSendBuf[MAXMSGLEN];
        memcpy(alohaSendBuf, &this->serverAlohaMsg, sizeof(serverAloha));
        if(send(connfd, alohaSendBuf, sizeof(alohaSendBuf), 0) < 0){
            perror("send msg error: ");
            exit(0);
        }
        break;
    }

    return connfd;
}

//handshake phase 2: certificate exchange (server)
size_t SSL::SSLServerCertificate(size_t connfd, size_t method)
{
    RSA RSA_Proc;

    /* CA info prepare */
    ULL param_CA;                 /* n */
    RSA_Proc.generate_keys();
    RSA_Proc.get_public_key(&this->publicKey_CA);
    RSA_Proc.get_private_key(&this->privateKey_CA);
    param_CA = RSA_Proc.getN();

    /* Server info prepare */
    ULL param_USER;               /* n */
    RSA_Proc.generate_keys();
    RSA_Proc.get_public_key(&this->publicKey_Server);
    RSA_Proc.get_private_key(&this->privateKey_Server);
    param_USER = RSA_Proc.getN();

    /* make server certificate */
    CA CAInstance(X509_V3, SYS_RSA, param_CA, this->publicKey_CA, this->serverMajorId, SYS_RSA, param_USER, this->publicKey_Server);
    Certificate serverCertificate = CAInstance.getCertificate();

    /* send server certificate */
    char certificateSendBuf[MAXMSGLEN];  
    memcpy(certificateSendBuf, &serverCertificate, sizeof(Certificate));
    if(send(connfd, certificateSendBuf, sizeof(Certificate), 0) < 0){
        perror("send msg error: ");
        exit(0);
    }

    /* make server abstract */
    byte *certificateByteForm = new byte[sizeof(Certificate)];

    for(size_t i = 0; i < sizeof(Certificate); i++) {
        certificateByteForm[i] = (byte)certificateSendBuf[i];
    }

    /***************************Print info********************************/
    std::cout << "Server certificate:" <<std::endl;
    for(size_t i = 0; i < sizeof(Certificate); i++) {
        std::cout << std::hex << certificateByteForm[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    byte serverAbstract[ABSTRACTLEN];
    sha512(certificateByteForm, serverAbstract, sizeof(Certificate));

    /***************************Print info********************************/
    std::cout << "Server abstract:" << std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << serverAbstract[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* get server certificate signature by encrypt the abstract with privateKey_CA */
    ULL serverSignature[ABSTRACTLEN];
    RSA_Proc.cipher(serverAbstract, serverSignature, &this->privateKey_CA, ABSTRACTLEN);

    /***************************Print info********************************/
    std::cout << "Server signature:" << std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << serverSignature[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* send server signature */
    __u_char signatureSendBuf[MAXMSGLEN];  
    memcpy(signatureSendBuf, serverSignature, sizeof(ULL) * ABSTRACTLEN);

    if(send(connfd, signatureSendBuf, ABSTRACTLEN * sizeof(ULL), 0) < 0){  
        perror("send msg error: ");
        exit(0);
    }

    /* receive client certificate */
    char certificateRecvBuf[MAXMSGLEN];  
    recv(connfd, certificateRecvBuf, sizeof(certificateRecvBuf), 0);
    Certificate clientCertificate;
    memcpy(&clientCertificate, certificateRecvBuf, sizeof(Certificate));

    /* receive client signature */
    __u_char signatureRecvBuf[MAXMSGLEN];  
    recv(connfd, signatureRecvBuf, sizeof(ULL) * ABSTRACTLEN, 0);

    ULL clientSignature[ABSTRACTLEN];   
    memcpy(clientSignature, signatureRecvBuf, sizeof(ULL) * ABSTRACTLEN);

    /***************************Print info********************************/
    std::cout << "Received client's signature:" << std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << clientSignature[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* get client certificate abstract by decrypt the signature with publicKey_CA */
    byte clientAbstract[ABSTRACTLEN];
    RSA_Proc.decipher(clientSignature, clientAbstract, &this->publicKey_CA, ABSTRACTLEN);

    /***************************Print info********************************/
    std::cout << "Clinet's abstract after decrypted:" << std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << clientAbstract[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* recalculate the client abstract */
    byte *_certificateByteForm = new byte[sizeof(Certificate)];
    for(size_t i = 0; i < sizeof(Certificate); i++) {
        _certificateByteForm[i] = (byte)certificateRecvBuf[i];
    }

    byte clientAbstractRecalculate[ABSTRACTLEN];
    sha512(_certificateByteForm, clientAbstractRecalculate, sizeof(Certificate));

    /***************************Print info********************************/
    std::cout << "Recalculated client's abstract:" << std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << clientAbstractRecalculate[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* authentication */
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        if(clientAbstractRecalculate[i].to_ulong() == clientAbstract[i].to_ulong())
            continue;
        else {
            std::cout << "Client Certificate authentication failed." << std::endl;
            exit(0);
        }
    }
    std::cout << "Client certificate authentication success." << std::endl << std::endl;

    size_t timeNow = time(NULL);
    if(clientCertificate.notAfter < timeNow) {
        std::cout << "Client Certificate expired." << std::endl;
        exit(0);
    }

    this->serverCertificate = serverCertificate;
    this->clientCertificate = clientCertificate;

    delete [] _certificateByteForm;
    delete [] certificateByteForm;

    return connfd;
}

//handshake phase 2: certificate exchange (client)
size_t SSL::SSLClientCertificate(size_t sockfd, size_t method)
{
    RSA RSA_Proc;
    /* CA info prepare */
    ULL param_CA;                /* n */
    RSA_Proc.generate_keys();
    RSA_Proc.get_public_key(&this->publicKey_CA);
    RSA_Proc.get_private_key(&this->privateKey_CA);
    param_CA = RSA_Proc.getN();

    /* receive server certificate*/
    char certificateRecvBuf[MAXMSGLEN];
    recv(sockfd, certificateRecvBuf, sizeof(Certificate), 0);
    Certificate *serverCertificate = (Certificate *)certificateRecvBuf;

    /* receive server signature */
    __u_char signatureRecvBuf[MAXMSGLEN];
    recv(sockfd, signatureRecvBuf, sizeof(ULL) * ABSTRACTLEN, 0);

    ULL serverSignature[ABSTRACTLEN];  
    memcpy(serverSignature, signatureRecvBuf, sizeof(ULL) * ABSTRACTLEN); 

    /***************************Print info********************************/
    std::cout << "Received server's signature:" <<std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << serverSignature[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* get server certificate abstract by decrypt the signature with publicKey_CA */
    byte serverAbstract[ABSTRACTLEN];
    RSA_Proc.decipher(serverSignature, serverAbstract, &this->publicKey_CA, ABSTRACTLEN);

    /***************************Print info********************************/
    std::cout << "Server's abstract after decrypted:" <<std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << serverAbstract[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* recalculate the server abstract */
    byte *_certificateByteForm = new byte[sizeof(Certificate)];
    for(size_t i = 0; i < sizeof(Certificate); i++) {
        _certificateByteForm[i] = (byte)certificateRecvBuf[i];
    }

    byte serverAbstractRecalculate[ABSTRACTLEN];
    sha512(_certificateByteForm, serverAbstractRecalculate,  sizeof(Certificate));

    /***************************Print info********************************/
    std::cout << "Recalculated server's abstract:" <<std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << serverAbstractRecalculate[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/
    
    /* authentication */
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        if(serverAbstractRecalculate[i].to_ulong() == serverAbstract[i].to_ulong())
            continue;
        else {
            std::cout << "Server Certificate authentication failed." << std::endl;
            exit(0);
        }
    }
    std::cout << "Server certificate authentication success." << std::endl << std::endl;

    size_t timeNow = time(NULL);
    if(serverCertificate->notAfter < timeNow) {
        std::cout << "Server Certificate expired." << std::endl;
        exit(0);
    }
    /* if success */

    /* Client info prepare */
    ULL param_USER;               /* n */
    RSA_Proc.generate_keys();
    RSA_Proc.get_public_key(&this->publicKey_Client);
    RSA_Proc.get_private_key(&this->privateKey_Client);
    param_USER = RSA_Proc.getN();

    /* make client certificate */
    CA CAInstance(X509_V3, SYS_RSA, param_CA, this->publicKey_CA, this->serverMajorId, SYS_RSA, param_USER, this->publicKey_Client);
    Certificate clientCertificate = CAInstance.getCertificate();
    
    /* send client certificate */
    char certificateSendBuf[MAXMSGLEN];
    memcpy(certificateSendBuf, &clientCertificate, sizeof(Certificate));
    if(send(sockfd, certificateSendBuf, sizeof(certificateSendBuf), 0) < 0){
        perror("send msg error: ");
        exit(0);
    }

    /* make client abstract */
    byte *certificateByteForm = new byte[sizeof(Certificate)];

    for(size_t i = 0; i < sizeof(Certificate); i++) {
        certificateByteForm[i] = (byte)certificateSendBuf[i];
    }

    /***************************Print info********************************/
    std::cout << "Client certificate:" <<std::endl;
    for(size_t i = 0; i < sizeof(Certificate); i++) {
        std::cout << std::hex << certificateByteForm[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    byte clientAbstract[ABSTRACTLEN];
    sha512(certificateByteForm, clientAbstract, sizeof(Certificate));

    /***************************Print info********************************/
    std::cout << "Client abstract:" <<std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << clientAbstract[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* get client certificate signature by encrypt the abstract with privateKey_CA */
    ULL clientSignature[ABSTRACTLEN];
    RSA_Proc.cipher(clientAbstract, clientSignature, &this->privateKey_CA, ABSTRACTLEN);

    /***************************Print info********************************/
    std::cout << "Client signature:" <<std::endl;
    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        std::cout << std::hex << clientSignature[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* send client signatre */
    __u_char signatureSendBuf[MAXMSGLEN];
    memcpy(signatureSendBuf, clientSignature, sizeof(ULL) * ABSTRACTLEN);

    if(send(sockfd, signatureSendBuf, ABSTRACTLEN * sizeof(ULL), 0) < 0){  
        perror("send msg error: ");
        exit(0);
    }

    this->clientCertificate = clientCertificate;
    this->serverCertificate = *serverCertificate;

    delete[] _certificateByteForm;
    delete[] certificateByteForm;

    return sockfd;
}

//handshake phase 3: session key exchange (client)
size_t SSL::SSLClientRSASessionKeyExchange(size_t sockfd)
{
    /* make session key (rsa) */
    RC4 RC4_Proc;
    byte key[5];
    srand((int)time(0));
    for(size_t i = 0; i < 5; i++) {
        key[i] = rand() % 256;
    }
    size_t keyLength = sizeof(key) / sizeof(key[0]);

    RC4_Proc.Initialize(key, keyLength);
    byte *sessionKeySend = RC4_Proc.GetRandom(16);

    /***************************Print info********************************/
    std::cout << "Client's session key:" << std::endl;
    for(size_t i = 0; i < 16; i++) {
        std::cout << std::hex << sessionKeySend[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* encrypt session key (16byte) with server's public key */
    RSA RSA_Proc;
    ULL encryptedSessionKey[16];
    RSA_Proc.cipher(sessionKeySend, encryptedSessionKey, &this->serverCertificate.publicKey_USER, 16);

    /***************************Print info********************************/
    std::cout << "Encrypted Client's Session Key:" << std::endl;
    for(size_t i = 0; i < 16; i++) {
        std::cout << std::hex << encryptedSessionKey[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* send session key from client */
    __u_char sessionKeySendBuf[MAXMSGLEN];  
    memcpy(sessionKeySendBuf, encryptedSessionKey, sizeof(ULL) * 16);

    if(send(sockfd, sessionKeySendBuf, 16 * sizeof(ULL), 0) < 0){  
        perror("send msg error: ");
        exit(0);
    }

    /***************************Print info********************************/
    std::cout << "Byte form Client's Session Key:" << std::endl;
    for(size_t i = 0; i < 16 * sizeof(ULL); i++) {
        std::cout << std::hex << (int)sessionKeySendBuf[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* receive session key from server */
    __u_char sessionKeyRecvBuf[MAXMSGLEN];  
    recv(sockfd, sessionKeyRecvBuf, sizeof(ULL) * 16, 0);

    /***************************Print info********************************/
    std::cout << "Byte form Server's Session Key:" << std::endl;
    for(size_t i = 0; i < 16 * sizeof(ULL); i++) {
        std::cout << std::hex << (int)sessionKeyRecvBuf[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    ULL sessionRecv[16];   
    memcpy(sessionRecv, sessionKeyRecvBuf, sizeof(ULL) * 16);

    /***************************Print info********************************/
    std::cout << "Encrypted Server's Session Key:" << std::endl;
    for(size_t i = 0; i < 16; i++) {
        std::cout << std::hex << sessionRecv[i] << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* decrypt received server's session key with client's private key */
    byte decryptedSessionKey[16];
    RSA_Proc.decipher(sessionRecv, decryptedSessionKey, &this->privateKey_Client, 16);

    /***************************Print info********************************/
    std::cout << "Decrypted server's session key:" << std::endl;
    for(size_t i = 0; i < 16; i++) {
        std::cout << std::hex << decryptedSessionKey[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*********************************************************************/

    /* authentication */
    for(size_t i = 0; i < 16; i++) {
        if(decryptedSessionKey[i].to_ulong() == sessionKeySend[i].to_ulong())
            continue;
        else {
            std::cout << "Session key disaccord, please retry." << std::endl;
            exit(0);
        }
    }
    std::cout << "Session key authentication success." << std::endl << std::endl;

    this->sessionKey = sessionKeySend;
    
    return sockfd;
}

//handshake phase 3: session key exchange (server)
size_t SSL::SSLServerRSASessionKeyExchange(size_t connfd)
{

    /* encrypt session key (16byte) with client's public key */
    RSA RSA_Proc;

    /* receive session key from client */
    __u_char sessionKeyRecvBuf[MAXMSGLEN];  
    recv(connfd, sessionKeyRecvBuf, sizeof(ULL) * 16, 0);

    ULL sessionRecv[16];   
    memcpy(sessionRecv, sessionKeyRecvBuf, sizeof(ULL) * 16);

    /* decrypt received client's session key with server's private key */
    byte decryptedSessionKey[16];
    RSA_Proc.decipher(sessionRecv, decryptedSessionKey, &this->privateKey_Server, 16);

    ULL encryptedSessionKey[16];
    RSA_Proc.cipher(decryptedSessionKey, encryptedSessionKey, &this->clientCertificate.publicKey_USER, 16);

    /* send session key from server */
    __u_char sessionKeySendBuf[MAXMSGLEN];  
    memcpy(sessionKeySendBuf, encryptedSessionKey, sizeof(ULL) * 16);

    if(send(connfd, sessionKeySendBuf, 16 * sizeof(ULL), 0) < 0){  
        perror("send msg error: ");
        exit(0);
    }

    this->sessionKey = decryptedSessionKey;
    
    return connfd;
}

//security transmission (client)
void SSL::SSLClientSecurityTransmission(size_t sockfd)
{
    SHA512 SHA_Proc;
    AES AES_Proc;

    /* AES prepare */
    word w[4*(Nr+1)];
    AES_Proc.KeyExpansion(this->sessionKey, w);

    /* input message */
    std::string msgInput;
    std::cout << "Input message:" << std::endl;
    getline(std::cin, msgInput);  
    std::cout << std::endl;

    if(msgInput == "quit") {
        close(sockfd);
        exit(0);
    }

    /* calculate send msg length */
    size_t fragNum = (msgInput.size() / FRAGMSGSIZE) + 1;
    size_t msgTotalSize = fragNum * FRAGMSGSIZE;

    /* get byte form message, and fill message with 0x00 */
    byte *msgByteForm = new byte[msgTotalSize];
    for(size_t i = 0; i < msgInput.size(); i++) {
        msgByteForm[i] = (byte)msgInput[i];
    }

    for(size_t i = msgInput.size(); i < msgTotalSize; i++) {
        msgByteForm[i] = 0x00; 
    }

    /*do fragment*/
    byte frag[FRAGMSGSIZE];
    for(size_t i = 0; i < msgTotalSize; i++) {
        frag[i % FRAGMSGSIZE] = msgByteForm[i];

        if((i + 1) % FRAGMSGSIZE == 0) {
            byte fragAbstract[ABSTRACTLEN];
            sha512(frag, fragAbstract, ABSTRACTLEN);

            byte beforeEncrypt[FRAGMSGSIZE + ABSTRACTLEN];
            
            for(size_t j = 0; j < FRAGMSGSIZE; j++) {
                beforeEncrypt[j] = frag[j];
            }
            for(size_t j = 0; j < ABSTRACTLEN; j++) {
                beforeEncrypt[FRAGMSGSIZE + j] = fragAbstract[j];
            }

            byte afterEncrypt[FRAGMSGSIZE + ABSTRACTLEN];
            byte temp[16];
            for(size_t j = 0; j < (FRAGMSGSIZE + ABSTRACTLEN); j++) {
                temp[j % 16] = beforeEncrypt[j];

                if((j + 1) % 16 == 0) {
                    AES_Proc.encrypt(temp, w);
                    for(size_t k = (j + 1) - 16; k < (j + 1); k++)
                        afterEncrypt[k] = temp[k % 16];
                }   
            }

            /*--------------------------------Print info-------------------------------------*/
            std::cout << "Plaintext and abstract before encryption:" << std::endl;
            for(size_t i = 0; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
                std::cout << std::hex << beforeEncrypt[i].to_ulong() << ' ';
            }
            std::cout << std::endl << std::endl; 

            std::cout << "Plaintext and abstract after encryption:" << std::endl;
            for(size_t i = 0; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
                std::cout << std::hex << afterEncrypt[i].to_ulong() << ' ';
            }
            std::cout << std::endl << std::endl;
            /*--------------------------------------------------------------------------------*/

            /* send message */
            char msgSendBuf[(FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte)];
            memcpy(msgSendBuf, afterEncrypt, (FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte));
            send(sockfd, msgSendBuf, (FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte), 0);
        }
    }
        delete[] msgByteForm;
}

//security transmission (server)
void SSL::SSLServerSecurityTransmission(size_t connfd)
{
    SHA512 SHA_Proc;
    AES AES_Proc;

    /* AES Prepare */
    word w[4*(Nr+1)];
    AES_Proc.KeyExpansion(this->sessionKey, w);

    std::cout << "Session key:" << std::endl;
    for(size_t i = 0; i < 16; i++) {
        std::cout << std::hex << this->sessionKey[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl << std::endl;

    /* receive encrypted message */
    char msgRecvBuf[(FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte)];
    if(recv(connfd, msgRecvBuf, (FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte), 0) == 0) {
        memset(msgRecvBuf, 0, sizeof((FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte)));
        std::cout << "Client exit." << std::endl;
        exit(0);
    }

    /* change encrypted message into byte form */
    byte beforeDecrypt[FRAGMSGSIZE + ABSTRACTLEN];
    memcpy(beforeDecrypt, msgRecvBuf, (FRAGMSGSIZE + ABSTRACTLEN) * sizeof(byte));

    /* decrypt received message */
    byte afterDecrypt[FRAGMSGSIZE + ABSTRACTLEN];
    byte temp[16];

    for(size_t i = 0; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
        temp[i % 16] = beforeDecrypt[i];

        if((i + 1) % 16 == 0) {
            AES_Proc.decrypt(temp, w);
            for(size_t j = (i + 1) - 16; j < (i + 1); j++)
                afterDecrypt[j] = temp[j % 16];
        }   
    }

    /* separate message into plaintext and abstract */
    byte msgFrag[FRAGMSGSIZE];
    byte fragAbstract[ABSTRACTLEN];
    for(size_t i = 0; i < FRAGMSGSIZE; i++) {
        msgFrag[i] = afterDecrypt[i];
    }
    for(size_t i = FRAGMSGSIZE; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
        fragAbstract[i - FRAGMSGSIZE] = afterDecrypt[i]; 
    }

    /* authentication */
    byte recalculateAbstract[ABSTRACTLEN];
    sha512(msgFrag, recalculateAbstract, ABSTRACTLEN);

    /*----------------------------Print info------------------------------------*/
    std::cout << "Plaintext and abstract before decryption:" << std::endl;
    for(size_t i = 0; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
        
        std::cout << std::hex << beforeDecrypt[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl; 

    std::cout << "Plaintext and abstract after decryption:" << std::endl;
    for(size_t i = 0; i < (FRAGMSGSIZE + ABSTRACTLEN); i++) {
        
        std::cout << std::hex << afterDecrypt[i].to_ulong() << ' ';
    }
    std::cout << std::endl << std::endl;
    /*---------------------------------------------------------------------------*/


    for(size_t i = 0; i < ABSTRACTLEN; i++) {
        if(fragAbstract[i].to_ulong() == recalculateAbstract[i].to_ulong())
            continue;
        else {
            std::cout << "Client's message abstract authentication failed." << std::endl;
            exit(0);
        }
    }
    
    /* show message and success info */
    std::cout << "Client's message abstract authentication success." << std::endl << std::endl;

    std::cout << "Received message:" << std::endl;
    for(size_t i = 0; i < FRAGMSGSIZE; i++) {
        std::cout << (char)msgFrag[i].to_ulong();
    }
    std::cout << std::endl << std::endl;
}
