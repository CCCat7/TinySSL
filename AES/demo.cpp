
#include "AES.h"

int main(int argc, char *argv[])
{
    AES *AES_proc = new AES();
	byte key[16] = {0x2b, 0x7e, 0x15, 0x16, 
					0x28, 0xae, 0xd2, 0xa6, 
					0xab, 0xf7, 0x15, 0x88, 
					0x09, 0xcf, 0x4f, 0x3c};
 
	byte plain[16] = {0x32, 0x88, 0x31, 0xe0, 
					0x43, 0x5a, 0x31, 0x37,
					0xf6, 0x30, 0x98, 0x07,
					0xa8, 0x8d, 0xa2, 0x34}; 
	// 输出密钥
	std::cout << "密钥是：";
	for(int i=0; i<16; ++i)
		std::cout << std::hex << key[i].to_ulong() << " ";
	std::cout << std::endl;
 
	word w[4*(Nr+1)];
	AES_proc->KeyExpansion(key, w);
 
	// 输出待加密的明文
	std::cout << std::endl << "待加密的明文："<< std::endl;
	for(int i=0; i<16; ++i)
	{
		std::cout << std::hex << plain[i].to_ulong() << " ";
		if((i+1)%4 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;
 
	// 加密，输出密文
	AES_proc->encrypt(plain, w);
	std::cout << "加密后的密文："<<std::endl;
	for(int i=0; i<16; ++i)
	{
		std::cout << std::hex << plain[i].to_ulong() << " ";
		if((i+1)%4 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;
 
	// 解密，输出明文
	AES_proc->decrypt(plain, w);
	std::cout << "解密后的明文："<< std::endl;
	for(int i=0; i<16; ++i)
	{
		std::cout << std::hex << plain[i].to_ulong() << " ";
		if((i+1)%4 == 0)
			std::cout << std::endl;
	}
	std::cout << std::endl;
	return 0;
}