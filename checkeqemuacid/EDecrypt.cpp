#include "EDecrypt.h"



EDecrypt::EDecrypt()
{
}


EDecrypt::~EDecrypt()
{
}






using namespace std; 



/////////////////// DES 加密/解密 ///////////////////////////// 

static const char des_pc1_table[56] = {

	56,48,40,32,24,16,8,

	0,57,49,41,33,25,17,

	9,1,58,50,42,34,26,

	18,10,2,59,51,43,35,

	62,54,46,38,30,22,14,

	6,61,53,45,37,29,21,

	13,5,60,52,44,36,28,

	20,12,4,27,19,11,3

};

// pc2选位表 

static const char des_pc2_table[48] = {

	13,16,10,23,0,4,2,27,

	14,5,20,9,22,18,11,3,

	25,7,15,6,26,19,12,1,

	40,51,30,36,46,54,29,39,

	50,44,32,47,43,48,38,55,

	33,52,45,41,49,35,28,31

};

// 左移位数表 

static const char des_loop_table[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };



// IP置换表 

static const char des_ip_table[64] = {

	57,49,41,33,25,17,9,1,

	59,51,43,35,27,19,11,3,

	61,53,45,37,29,21,13,5,

	63,55,47,39,31,23,15,7,

	56,48,40,32,24,16,8,0,

	58,50,42,34,26,18,10,2,

	60,52,44,36,28,20,12,4,

	62,54,46,38,30,22,14,6

};



// IP-1 逆置换表 

static const char des_ip_r_table[64] = {

	39,7,47,15,55,23,63,31,

	38,6,46,14,54,22,62,30,

	37,5,45,13,53,21,61,29,

	36,4,44,12,52,20,60,28,

	35,3,43,11,51,19,59,27,

	34,2,42,10,50,18,58,26,

	33,1,41,9,49,17,57,25,

	32,0,40,8,48,16,56,24

};



// E 选位表 

static const char des_e_table[48] = {

	31,0,1,2,3,4,

	3,4,5,6,7,8,

	7,8,9,10,11,12,

	11,12,13,14,15,16,

	15,16,17,18,19,20,

	19,20,21,22,23,24,

	23,24,25,26,27,28,

	27,28,29,30,31,0

};



// S盒 

static const char des_s_box[8][4][16] = {

	//S1 

	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,

	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,

	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,

	15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13,

	//S2 

	15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,

	3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,

	0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,

	13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9,

	//S3 

	10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,

	13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,

	13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,

	1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12,

	//S4 

	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,

	13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,

	10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,

	3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14,

	//S5 

	2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,

	14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,

	4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,

	11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3,

	//S6 

	12,1,10,15,9,2,6,8,0,12,3,4,14,7,5,11,

	10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,

	9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,

	4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13,

	//S7 

	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,

	13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,

	1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,

	6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12,

	//S8 

	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,

	1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,

	7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,

	2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11

};



// p选位表 

static const char des_p_table[32] = {

	15,6,19,20,28,11,27,16,

	0,14,22,25,4,17,30,9,

	1,7,23,13,31,26,2,8,

	18,12,29,5,21,10,3,24

};







// 字节组转成位组 

void EDecrypt::byte_to_bit(char *out, const char *in, int bits) 

{ 

int i; 

for(i=0; i<bits; i++) 

*out++ = (in[(i&~7)>>3]>>(i&7)) & 1; 

} 



// 位组转成字节组 

void EDecrypt::bit_to_byte(char *out, const char *in, int bits)

{ 

int i; 

memset(out,0,((bits+7)&~7)>>3); 

for(i=0; i<bits; i++) 

out[(i&~7)>>3] |= (*in++) << (i&7); 

} 



// 置换 

void EDecrypt::des_transform(char *out, char *in, const char *table, int len)

{ 

static char tmp[64]; 

int i; 

char *p = tmp; 



for (i=0; i<len; i++) 

*p++ = in[*table++]; 



memcpy(out, tmp, len); 

} 





void EDecrypt::xor(char *a, const char *b, int len)

{ 

while (len--) 

*a++ ^= *b++; 

} 



// S盒 

void EDecrypt::des_s_transform(char out[32], const char in[48])

{ 

int b,r,c; 

for (b=0; b<8; out+=4,in+=6,b++) 

{ 

r = (in[0]<<1) | in[5]; 

c = (in[1]<<3) | (in[2]<<2) | (in[3]<<1) | in[4]; 

byte_to_bit(out, &des_s_box[b][r][c], 4); 

} 

} 



// 循环左移 

void EDecrypt::des_left_loop(char *in, int loop)

{ 

static bool tmp[2]; 

memcpy(tmp,in,loop); 

memcpy(in,in+loop,28-loop); 

memcpy(in+28-loop,tmp,loop); 

} 



// 16个子密钥 

void EDecrypt::des_make_subkeys(const char key[8], char subkeys[16][48])

{ 

char bits[64]; 

char *r=bits+28; 

int i; 



byte_to_bit(bits, key, 64); 

des_transform(bits,bits,des_pc1_table, 56); 

for (i=0; i<16; i++) 

{ 

des_left_loop(bits, des_loop_table[i]); 

des_left_loop(r, des_loop_table[i]); 

des_transform(subkeys[i],bits,des_pc2_table,48); 

} 

} 



// 混合数据和密钥 

void EDecrypt::des_mix(char in[32], const char key[48])

{ 

static char r[48]; 



des_transform(r,in,des_e_table,48); 

xor(r,key,48); 

des_s_transform(in,r); 

des_transform(in,in,des_p_table,32); 

} 



// 加密/解密 

void EDecrypt::des_go(char out[8], const char in[8], bool encrypt)

{

static char data[64]; 

static char tmp[32]; 

static char *r=data + 32; 

unsigned char k[8] = {0};

int i; 

des_make_subkeys((char*)k,subkeys);

byte_to_bit(data, in, 64); 

des_transform(data, data, des_ip_table, 64); 



if (encrypt) // 加密 

{ 

for (i=0; i<16; i++) 

{ 

memcpy(tmp, r, 32); 

des_mix(r, subkeys[i]); 

xor(r, data, 32); 

memcpy(data, tmp, 32); 

} 

} 

else // 解密 

{ 

for (i=15; i>=0; i--) 

{ 

memcpy(tmp, data, 32); 

des_mix(data, subkeys[i]); 

xor(data, r, 32); 

memcpy(r, tmp, 32); 

} 

} 

des_transform(data, data, des_ip_r_table, 64); 

bit_to_byte(out, data, 64); 

} 
