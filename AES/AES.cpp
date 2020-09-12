#include "AES.h"

AES::AES() {}

AES::~AES() {}

word AES::GetWord(byte &k1, byte &k2, byte &k3, byte &k4)
{
	word result(0x00000000);
	word temp;
	temp = k1.to_ulong();  // K1
	temp <<= 24;
	result |= temp;
	temp = k2.to_ulong();  // K2
	temp <<= 16;
	result |= temp;
	temp = k3.to_ulong();  // K3
	temp <<= 8;
	result |= temp;
	temp = k4.to_ulong();  // K4
	result |= temp;
	return result;
}

word AES::RotateWord(word &rw)
{
	word high = rw << 8;
	word low = rw >> 24;
	return high | low;
}

word AES::SubWord(word const &sw)
{
	word temp;
	for(size_t i = 0; i < 32; i += 8) {
		size_t row = sw[i+7]*8 + sw[i+6]*4 + sw[i+5]*2 + sw[i+4];
		size_t col = sw[i+3]*8 + sw[i+2]*4 + sw[i+1]*2 + sw[i];
		byte val = this->S_Box[row][col];
		for(size_t j = 0; j < 8; ++j) {
            temp[i+j] = val[j];
        }
	}
	return temp;
}

void AES::KeyExpansion(byte key[4*Nk], word w[4*(Nr+1)])
{
    for(size_t i = 0; i < 4; i++) {             //get w0~w3
        w[i] = GetWord(key[4*i], key[4*i + 1], key[4 * i + 2], key[4 * i + 3]);
    }

    word temp;
    for(size_t i = 4; i < 4*(Nr+1); i++) {
        temp = w[i - 1]; // 记录前一个word w3
		if(i % Nk == 0)
			w[i] = w[i-Nk] ^ SubWord(RotateWord(temp)) ^ Rcon[i/Nk-1];
		else 
			w[i] = w[i-Nk] ^ temp;
    }
}

void AES::SubBytes(byte mtx[4*4])
{
	for(size_t i = 0; i < 16; i++)
	{
		size_t row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
		size_t col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
		mtx[i] = this->S_Box[row][col];
	}
}

void AES::ShiftRows(byte mtx[4*4])
{
	// 第二行循环左移一位
	byte temp = mtx[4];
	for(size_t i = 0; i < 3; i++)
		mtx[i+4] = mtx[i+5];
	mtx[7] = temp;

	// 第三行循环左移两位
	for(size_t i = 0; i < 2; i++)
	{
        byte b = 0x01;
        byte a = b & byte(1);
		temp = mtx[i+8];
		mtx[i+8] = mtx[i+10];
		mtx[i+10] = temp;
	}

	// 第四行循环左移三位
	temp = mtx[15];
	for(size_t i = 3; i > 0; i--)
		mtx[i+12] = mtx[i+11];
	mtx[12] = temp;
}

byte AES::GFMul(byte a, byte b) { 
	byte p = 0;
	byte hi_bit_set;
	for (size_t counter = 0; counter < 8; counter++) {
		if ((b & byte(1)) != 0) {
			p ^= a;
		}
		hi_bit_set = (byte) (a & byte(0x80));
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}

void AES::MixColumns(byte mtx[4*4])
{
	byte arr[4];
	for(size_t i = 0; i < 4; i++) {
		for(size_t j = 0; j < 4; j++)
			arr[j] = mtx[i+j*4];
 
		mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
		mtx[i+4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
		mtx[i+8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
		mtx[i+12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
	}
}

void AES::AddRoundKey(byte mtx[4*4], word k[4])
{
	for(size_t i = 0; i < 4; i++) {
		word k1 = k[i] >> 24;
		word k2 = (k[i] << 8) >> 24;
		word k3 = (k[i] << 16) >> 24;
		word k4 = (k[i] << 24) >> 24;
		
		mtx[i] = mtx[i] ^ byte(k1.to_ulong());
		mtx[i+4] = mtx[i+4] ^ byte(k2.to_ulong());
		mtx[i+8] = mtx[i+8] ^ byte(k3.to_ulong());
		mtx[i+12] = mtx[i+12] ^ byte(k4.to_ulong());
	}
}

void AES::InvSubBytes(byte mtx[4*4])
{
	for(size_t i = 0; i < 16; i++) {
		size_t row = mtx[i][7]*8 + mtx[i][6]*4 + mtx[i][5]*2 + mtx[i][4];
		size_t col = mtx[i][3]*8 + mtx[i][2]*4 + mtx[i][1]*2 + mtx[i][0];
		mtx[i] = this->Inv_S_Box[row][col];
	}
}

void AES::InvShiftRows(byte mtx[4*4])
{
	// 第二行循环右移一位
	byte temp = mtx[7];
	for(size_t i = 3; i > 0; i--)
		mtx[i+4] = mtx[i+3];
	mtx[4] = temp;

	// 第三行循环右移两位
	for(size_t i = 0; i < 2; i++) {
		temp = mtx[i+8];
		mtx[i+8] = mtx[i+10];
		mtx[i+10] = temp;
	}

	// 第四行循环右移三位
	temp = mtx[12];
	for(size_t i = 0; i < 3; i++)
		mtx[i+12] = mtx[i+13];
	mtx[15] = temp;
}
 
void AES::InvMixColumns(byte mtx[4*4])
{
	byte arr[4];
	for(size_t i = 0; i < 4; i++) {
		for(size_t j = 0; j < 4; j++)
			arr[j] = mtx[i+j*4];
 
		mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
		mtx[i+4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
		mtx[i+8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
		mtx[i+12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
	}
}

void AES::encrypt(byte in[4*4], word w[4*(Nr+1)])
{
	word key[4];
	for(size_t i = 0; i < 4; i++)
		key[i] = w[i];
	AddRoundKey(in, key);
 
	for(size_t round = 1; round < Nr; round++) {
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for(size_t i = 0; i < 4; i++)
			key[i] = w[4*round+i];
		AddRoundKey(in, key);
	}
 
	SubBytes(in);
	ShiftRows(in);
	for(size_t i = 0; i < 4; i++)
		key[i] = w[4*Nr+i];
	AddRoundKey(in, key);
}

void AES::decrypt(byte in[4*4], word w[4*(Nr+1)])
{
	word key[4];
	for(size_t i = 0; i < 4; i++)
		key[i] = w[4*Nr+i];
	AddRoundKey(in, key);
 
	for(size_t round = Nr-1; round > 0; round--)
	{
		InvShiftRows(in);
		InvSubBytes(in);
		for(size_t i = 0; i < 4; i++)
			key[i] = w[4*round+i];
		AddRoundKey(in, key);
		InvMixColumns(in);
	}
 
	InvShiftRows(in);
	InvSubBytes(in);
	for(size_t i = 0; i < 4; i++)
		key[i] = w[i];
	AddRoundKey(in, key);
}
