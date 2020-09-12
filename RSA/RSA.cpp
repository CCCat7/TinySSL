//
//  RSA.cpp
//  RSA
//
//  Created by Jingyuan Chen on 2020/6/11.
//  Copyright © 2020年 Jingyuan Chen. All rights reserved.
//

#include "RSA.h"
#include <cassert>
#include <fstream>

void RSA::generate_keys() {
    generate_two_big_primes(p, q);
    phi = (p - 1) * (q - 1);
    n = p * q;
    ULL y;
    while(true) {
        e = ran() % (phi - 3) + 3;
        if (phi % e == 0) continue;
        ULL gcd = exgcd(e, phi, d, y);
        if (gcd == 1u && d > 0 && d < n) break;
    }
}

ULL mod_pro(ULL x, ULL y, ULL n) {
    ULL ret = 0, tmp = x % n;
    while(y) {
        if (y & 0x1)
            if((ret += tmp) > n) ret -= n;
        if ((tmp <<= 1) > n) tmp -= n;
        y >>= 1;
    }
    return ret;
}

ULL mod(ULL a, ULL b, ULL c) {
    ULL ret = 1;
    while(b) {
        if (b & 0x1) ret = mod_pro(ret, a, c);
        a = mod_pro(a, a, c);
        b >>= 1;
    }
    return ret;
}

ULL RSA::ran() {
    ULL ret = rand();
    return (ret << 31) + rand();
}

bool RSA::is_prime(ULL n, int t) {
    if(n < 2) return false;
    if(n == 2) return true;
    if(n % 2 == 0) return false;
    
    ULL k = 0, m, a, i;
    for(m = n - 1; !(m & 1); m >>= 1, ++k);
    while(t--) {
        a = mod(ran() % (n - 2) + 2, m, n);
        if(a != 1) {
            for(i = 0; i < k && a != n - 1; ++i)
                a = mod_pro(a, a, n);
            if(i >= k) return false;
        }
    }
    
    return true;
}

int RSA::enum_prime_less_than(int n, UI *p) {
    if (n <= 2) return 0;
    bool *notPrime = new bool[n + 1];
    memset(notPrime, 0, sizeof(bool) * (n + 1));
    
    int cnt = 0;
    p[0] = 1;
    
    int tmp;
    for (int i = 2; i < n; ++i) {
        if (!notPrime[i]) p[++cnt] = i;
        for (int j = 1; j <= cnt; ++j) {
            if ((tmp = p[j] * i) >= n) break;
            notPrime[tmp] = true;
            if (i % p[j] == 0) break;
        }
    }
    delete [] notPrime;
    return cnt;
}

void RSA::generate_two_big_primes(ULL &a, ULL &b) {
    //srand((int)time(0));
    size_t indexA = rand() % 100;
    size_t indexB = rand() % 100;
    while (indexA == indexB) {
        indexB = rand() % 100;
    }
    
    a = prime[indexA];
    b = prime[indexB];
}

ULL RSA::exgcd(ULL a, ULL b, ULL& x, ULL& y) {
    if(b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    
    ULL gcd = exgcd(b, a % b, x, y);
    ULL t = y;
    y = x - (a / b) * (y);
    x = t;
    return gcd;
}

void RSA::byte_to_int_array(byte* b, ULL* u) {
    
    //每个byte装入一个unsigned long long中
    for (size_t i = 0; i < keylen; ++i) {
        u[i] = b[i].to_ullong();
    }
}

void RSA::int_to_byte_array(byte* b, ULL* u) {
    
    for (size_t i = 0; i < keylen; ++i) {
        std::bitset<8> bs(u[i]);
        b[i] = bs;
    }
}

void RSA::cipher(byte* In, ULL* Out, std::pair<ULL, ULL> *key, size_t len) {
    
    keylen = len;
    ULL *in = new ULL[keylen];
    
    byte_to_int_array(In, in);
    
    e = key->first;
    n = key->second;

    for (size_t i = 0; i < keylen; i++) {
        assert(in[i] < n);
        Out[i] = mod(in[i], e, n);
    }

    delete [] in;
}

void RSA::decipher(ULL* In, byte* Out, std::pair<ULL, ULL> *key, size_t len) {
    
    keylen = len;
    ULL *out = new ULL[keylen];
    
    d = key->first;
    n = key->second;
    
    for (size_t i = 0; i < keylen; i++) {
        out[i] = mod(In[i], d, n);
    }
    
    int_to_byte_array(Out, out);
    
    delete [] out;
}
