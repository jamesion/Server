#pragma once
#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
using namespace std;

class EDecrypt
{
public:
	EDecrypt();
	~EDecrypt();

	// pc1Ñ¡Î»±í 




	static char subkeys[16][48];
	void byte_to_bit(char *out, const char *in, int bits);
	void bit_to_byte(char *out, const char *in, int bits);

	void des_transform(char *out, char *in, const char *table, int len);

	void xor(char *a, const char *b, int len);
	

	void des_s_transform(char out[32], const char in[48]);
	void des_left_loop(char *in, int loop);
	void des_make_subkeys(const char key[8], char subkeys[16][48]);
	void des_mix(char in[32], const char key[48]);
	void des_go(char out[8], const char in[8], bool encrypt);

};

