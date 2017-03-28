#ifndef EQEMU_CACID_H
#define EQEMU_CACID_H

#define _WINDOWS 1

#include "WinSock2.h"
#include "iostream"
#include "stdio.h"
#include "Windows.h"
#include "../common/random.h"
#include "../common/types.h"

#ifndef WIN32
#include "eq_crypto_api.h"
#endif
#include <string>
#pragma comment(lib, "ws2_32.lib")  


#define HOST_IP "10.18.159.58"    //eqemu loginserver_ip is 66.55.145.2
#define HOST_PORT 5999


#ifndef WIN32
#include "../../loginserver/eq_crypto_api.h"
#endif
#include <string>
#include <stdint.h>
typedef uint8_t byte;
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

using namespace std;


#pragma once



class CheckEmuAcid
{
public:
	unsigned int emu_acc_id;


	//服务器返回准进确认信息存放
	struct ServerAccepted_Struct {
		short unknown1;
		short unknown2;
		short unknown3;
		short unknown4;
		short unknown5;
		char encrypt[80];
	};

	struct RecvBuff {
		uchar BrecvBuf[255];
		uchar *pbuff;
		int pBuf_len=0;
	};

	//解密后信息存放
	struct ServerFailedAttempts_Struct
	{
		char message; //0x01
		char unknown2[7]; //0x00
		uint32 lsid;
		char key[11]; //10 char + null term;
		uint32 failed_attempts;
		char unknown3[4];	//0x00, 0x00, 0x00, 0x03
		char unknown4[4];	//0x00, 0x00, 0x00, 0x02
		char unknown5[4];	//0xe7, 0x03, 0x00, 0x00
		char unknown6[4];	//0xff, 0xff, 0xff, 0xff
		char unknown7[4];	//0xa0, 0x05, 0x00, 0x00
		char unknown8[4];	//0x00, 0x00, 0x00, 0x02
		char unknown9[4];	//0xff, 0x03, 0x00, 0x00
		char unknown10[4];	//0x00, 0x00, 0x00, 0x00
		char unknown11[4];	//0x63, 0x00, 0x00, 0x00
		char unknown12[4];	//0x01, 0x00, 0x00, 0x00
		char unknown13[4];	//0x00, 0x00, 0x00, 0x00
		char unknown14[4];	//0x00, 0x00, 0x00, 0x00
	};



	CheckEmuAcid();
	~CheckEmuAcid();




 //声明一个发出请求缓存
	unsigned  char readyrequest[14]  
	{
		0x02,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x0B,0x00
	};
	unsigned  char send1[14]
	{
		0x00,0x01,0x00,0x00,0x00,0x02,0x7b,
		0x9d,0x0c,0xdb,0x00,0x00,0x02,0x00
	};
	unsigned  char send2[20]
	{
		0x00,0x09,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0x0b,0xda
	}; 
	unsigned char send3[42]
	{
		0x00,0x03,0x04,0x00,0x15,0x00,0x00,0x20,0x00,0x09,0x00,0x01,0x02,0x00,0x03,0x00,0x00,0x00,0x00,0x02,0x00,
		0x00,0x00,0x00,0x52,0x2f,0x74,0xa9,0x7e,0xe3,0x3d,0xbc,0x3d,0xdb,0x00,0x96,0x36,0xf1,0xd3,0x98,0x24,0xf3
	};



void emulisentfrom(SOCKET socket, unsigned short port);

public:
	

	void dumpbuffhex(unsigned char *buff, int size);
	unsigned char *sendtoemu(SOCKET socket,unsigned short por,unsigned char *sendbuff,int size);
	SOCKET connountto();
	unsigned short ceidbind(SOCKET socket);

	void DumpPacketHex(const uchar* buf, uint32 size, uint32 cols = 16, uint32 skip = 0);
	std::string DumpPacketHexToString(const uchar* buf, uint32 size, uint32 cols = 16, uint32 skip = 0);
	
};

#endif