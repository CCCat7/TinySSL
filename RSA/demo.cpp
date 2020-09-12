//
//  main.cpp
//  RSA
//
//  Created by Jingyuan Chen on 2020/6/11.
//  Copyright © 2020年 Jingyuan Chen. All rights reserved.
//

#include "RSA.h"
#include <iostream>

int main(int argc, const char * argv[]) {
    size_t len = 16;
    
    //get keys
    std::pair<ULL, ULL> pb, pv;// (e,n), (d,n)
    RSA getkeys;
    getkeys.generate_keys();
    getkeys.get_public_key(&pb);
    getkeys.get_private_key(&pv);
    std::cout << pb.first << "\t" << pb.second << std::endl;
    std::cout << pv.first << "\t" << pv.second << std::endl;
    
    //use keys
    byte orign[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };
    
    ULL *secretb = new ULL[len];
    byte *originb = new byte[len];
    RSA test;
    test.cipher(orign, secretb, &pb, len);//公钥加密会话密钥
    test.decipher(secretb, originb, &pv, len);//私钥解密会话密钥

//    byte *secretb = new byte[len];
//    byte *originb = new byte[len];
//    RSA test;
//    test.endecryption(orign, secretb, &pb, len);//公钥加密会话密钥
//    test.endecryption(secretb, originb, &pv, len);//私钥解密会话密钥


    return 0;
}
