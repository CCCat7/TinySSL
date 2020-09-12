//
//  RSA.h
//  RSA
//
//  Created by Jingyuan Chen on 2020/6/11.
//  Copyright © 2020年 Jingyuan Chen. All rights reserved.
//

#ifndef RSA_H
#define RSA_H

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <bitset>
#include <map>

typedef std::bitset<8> byte;
typedef unsigned long long ULL;
typedef unsigned int UI;

class RSA{
public:
    RSA(){};
    ~RSA(){};
    
    void generate_keys();
    
    void get_public_key(std::pair<ULL, ULL> *pb) {
        pb->first = e;
        pb->second = n;
    }
    
    void get_private_key(std::pair<ULL, ULL> *pv) {
        pv->first = d;
        pv->second = n;
    }
    
    void cipher(byte* origin, ULL* secret, std::pair<ULL, ULL> *key, size_t len);
    void decipher(ULL* origin, byte* secret, std::pair<ULL, ULL> *key, size_t len);
    ULL getN() {
        return this->n;
    }
private:
    ULL p, q, n, phi, e, d;
    size_t keylen;
    
    ULL ran();
    bool is_prime(ULL n,int t);
    int enum_prime_less_than(int n, UI *p);
    void generate_two_big_primes(ULL &a, ULL &b);
    ULL exgcd(ULL a, ULL b, ULL& x, ULL& y);
    void byte_to_int_array(byte* b, ULL* uint);
    void int_to_byte_array(byte* b, ULL* uint);
};

const UI prime[100] = {
    64373,64381,64399,64403,64433,64439,64451,64453,64483,64489,
    64499,64513,64553,64567,64577,64579,64591,64601,64609,64613,
    64621,64627,64633,64661,64663,64667,64679,64693,64709,64717,
    64747,64763,64781,64783,64793,64811,64817,64849,64853,64871,
    64877,64879,64891,64901,64919,64921,64927,64937,64951,64969,
    64997,65003,65011,65027,65029,65033,65053,65063,65071,65089,
    65099,65101,65111,65119,65123,65129,65141,65147,65167,65171,
    65173,65179,65183,65203,65213,65239,65257,65267,65269,65287,
    65293,65309,65323,65327,65353,65357,65371,65381,65393,65407,
    65413,65419,65423,65437,65447,65449,65479,65497,65519,65521
};

#endif

