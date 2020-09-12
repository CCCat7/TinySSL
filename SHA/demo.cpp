//
//  main.cpp
//  SHA
//
//  Created by Jingyuan Chen on 2020/6/9.
//  Copyright © 2020年 Jingyuan Chen. All rights reserved.
//

#include "SHA.h"
#include <iostream>

void printByte(byte *b, size_t len);

int main(int argc, const char * argv[])
{
    byte *in = new byte[104];
    for (size_t i = 0; i < 104; i++) {
        in[i] = (byte)i;
    }
    byte *out = new byte[64];
    sha512(in, out, 104);

    for (size_t i = 0; i < 64; i++) {
        std::cout << out[i].to_ulong() << ' ';
    }

    std::cout << std::endl;
//    size_t bytenum = 104;
//    size_t abssize = 64;
//
//    byte orign[104] = {
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6,
//        0xab, 0xf7, 0x15, 0x88,
//        0x09, 0xcf, 0x4f, 0x3c,
//
//        0x2b, 0x7e, 0x15, 0x16,
//        0x28, 0xae, 0xd2, 0xa6
//    };
//
//    std::cout << "摘要输入(16进制表示)：" << std::endl;
//    printByte(orign, bytenum);
//
//    byte *encryption = new byte[abssize];
//
//    //SHA摘要求解函数
//    //参数为输入和byte数，消息长度应小于2 ^ 128
//    sha512(orign, encryption, bytenum);
//
//    std::cout << "摘要求解结果(512bits)：" << std::endl;
//    printByte(encryption, abssize);
//
    return 0;
}

void printByte(byte *b, size_t len)
{
    unsigned long *ui = new unsigned long[len];
    for (size_t i = 0; i < len; ++i) {
        ui[i] = b[i].to_ulong();
    }
    
    //每4个byte装入一个unsigned long long中
    size_t chsize = len * 2;
    char *temp = new char[chsize];
    for (size_t i = 0; i < len; ++i) {
        sprintf(temp, "%s%02x", temp, (unsigned int)ui[i]);
    }
    temp[chsize] = '\0';
    
    std::cout << temp << std::endl << std::endl;
}
