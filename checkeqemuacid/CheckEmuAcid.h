#ifndef EQEMU_CACID_H
#define EQEMU_CACID_H

#define _WINDOWS 1

#include "WinSock2.h"
#include "iostream"
#include "stdio.h"
#include "Windows.h"
#include "../common/random.h"
#include "../common/types.h"
#include "encryption.h"
//#include "EDecrypt.h"

#ifndef WIN32
#include "../loginserver/eq_crypto_api.h"
#endif
#include <string>
#pragma comment(lib, "ws2_32.lib")  




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


#define HOST_IP "192.168.43.135"    //eqemu loginserver_ip is 66.55.145.2
#define HOST_PORT 5999


class CheckEmuAcid
{
public:
	unsigned int emu_ac_id;
	uchar recvbuf[255] = { 0 };
	//服务器返回准进确认信息存放
	struct ServerAccepted_Struct {
		short head[3];
		short unknown1;
		short unknown2;
		short unknown3;
		short unknown4;
		short unknown5;
		char encrypt[80];
	};
	//分解接收包OP
	struct ServerRecv_Struct {
		uchar unknown1;
		uchar op;
		uchar unknown2[4];
		uchar para;
		uchar unknown3;
	};

	struct RecvBuff {
		uchar *pbuff;
		int pBuf_len=0;
		bool getlsid = false;
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
	unsigned  char clienup[14]
	{
		0x00,0x01,0x00,0x00,0x00,0x02,0x0e,0x00,0xac,0x3b,0x00,0x00,0x02,0x00
	};
	unsigned  char sure[20]
	{
		0x00,0x09,0x00,0x00,0x01,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0b,0x00,0xdd,0x00
	}; 
	unsigned  char sure0[20]
	{

		0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x93, 0x1f

	};
	unsigned char account[42]
	{
		0x00,0x03,0x04,0x00,0x15,0x00,0x00,0x20,0x00,0x09,0x00,0x01,0x02,0x00,0x03,0x00,0x00,0x00,0x00,0x02,0x00,0x00,

		0x00,0x00,0x52,0x2f,0x74,0xa9,0x7e,0xe3,0x3d,0xbc,0x3d,0xdb,0x00,0x96,0x36,0xf1,0xd3,0x98,0x85,0x78
		
	};

	unsigned char end0[4]
	{
		0x00,0x15,0x00,0x0f
	};

	unsigned char end1[16]
	{
		0x00,0x09,0x00,0x03,0x03,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
	unsigned char end2[8]
	{
		0x00,0x05,0x16,0xf5,0x8c,0x7f,0x00,0x06
	};

	unsigned char end3[10]
	{
		0x00,0x05,0x0e,0x00,0xac,0x3b,0x00,0x06,0x81,0x41
	};


	RecvBuff recv[10] = { 0 };

	ServerFailedAttempts_Struct *decrypt;

public:
	
	uint32  getemulsid();

private:
	int		sendtoemu(SOCKET socket/*,unsigned short por*/);
	SOCKET  connountto();
	//unsigned short ceidbind(SOCKET socket);
	void	DumpPacketHex(const uchar* buf, uint32 size, uint32 cols = 16, uint32 skip = 0);
	std::string DumpPacketHexToString(const uchar* buf, uint32 size, uint32 cols = 16, uint32 skip = 0);
	uint32 cryptoidbuff(int acidbuf_id);
	
public:

private:
	int emusendto(unsigned char*  send, int Size, SOCKET socket, SOCKADDR_IN addrSrv);
};

#endif