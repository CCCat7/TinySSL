#include "RC4.h"

RC4::RC4(){}

RC4::~RC4(){}

void RC4::Swap(byte &a, byte &b)
{
    byte temp = a;
    a = b; 
    b = temp;
}

void RC4::Initialize(byte *key, size_t length)
{
    //initialize
    for(size_t i = 0; i < 256; i++) {
        this->S[i] = i;
        this->T[i] = key[i % length];
    }

    //states rearrangement
    size_t j = 0;
    for(size_t i = 0; i < 256; i++) {
        j = (j + S[i].to_ulong() + T[i].to_ulong()) % 256;
        Swap(S[i], S[j]);
    }
}

void RC4::Encryption(byte *data, size_t length)
{
    //random generation
    size_t i, j = 0;

    for(size_t k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + (this->S[i]).to_ulong()) % 256;
        Swap(S[i], S[j]);

        size_t t = ((this->S[i]).to_ulong() + (this->S[j]).to_ulong()) % 256;
        data[k] ^= this->S[t];
    }
}

byte *RC4::GetRandom(size_t length)
{
    byte *randomNums = new byte[length];
    //random generation
    size_t i, j = 0;

    for(size_t k = 0; k < length; k++) {
        i = (i + 1) % 256;
        j = (j + (this->S[i]).to_ulong()) % 256;
        Swap(S[i], S[j]);

        size_t t = ((this->S[i]).to_ulong() + (this->S[j]).to_ulong()) % 256;
        randomNums[k] = (this->S[t]);
    }
    return randomNums;
}