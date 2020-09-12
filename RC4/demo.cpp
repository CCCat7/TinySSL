#include "RC4.h"

int main(int argc, char* argv[])
{
    byte key[] = {0x13, 0x17, 0x21, 0x11, 0x64};
    byte data[] = {0xab, 0xa7, 0xc3, 0x01};
    size_t keyLength = sizeof(key) / sizeof(key[0]);
    size_t dataLength = sizeof(data) / sizeof(data[0]);

    for(size_t i = 0; i < dataLength; i++)
        std::cout << std::hex << data[i].to_ulong() << ' ';
    std::cout << std::endl;
    
    RC4 *RC4_proc = new RC4();
    RC4_proc->Initialize(key, keyLength);
    RC4_proc->Encryption(data, dataLength);

    for(size_t i = 0; i < dataLength; i++)
        std::cout << std::hex << data[i].to_ulong() << ' ';
    std::cout << std::endl;
    
    RC4_proc->Initialize(key, keyLength);
    RC4_proc->Encryption(data, dataLength);

    for(size_t i = 0; i < dataLength; i++)
        std::cout << std::hex << data[i].to_ulong() << ' ';
    std::cout << std::endl;

    RC4_proc->Initialize(key, keyLength);
    byte *randomNums;
    randomNums = RC4_proc->GetRandom(10);
    for(size_t i = 0; i < 10; i++) {
        std::cout << std::hex << (randomNums + i)->to_ulong() << std::endl;
    }
    return 0;
}