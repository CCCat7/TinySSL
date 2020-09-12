#ifndef _RC4_H
#define _RC4_H

#include <iostream>
#include <cstdlib>
#include <algorithm>
#include <sys/types.h>
#include <cstring>
#include <vector>
#include <bitset>

typedef std::bitset<8> byte;

class RC4
{
private:
    byte S[256], T[256];
public:
    RC4();
    ~RC4();
    void Initialize(byte *key, size_t length);
    void Swap(byte &a, byte &b);
    void Encryption(byte *data, size_t length);
    byte *GetRandom(size_t length);
};

#endif