#include "CheckEmuAcid.h"


void main(string IP, string name, string password) 
{
	CheckEmuAcid *checkid = new CheckEmuAcid();
	

	int i=0,acidbuf_id = 0;
	SOCKET hostsocket = 0;
	unsigned short port;
	closesocket(hostsocket);
	WSACleanup();

	if (!(hostsocket= checkid->connountto()))
	{
		cout <<"Socket建立失败!!"<<endl;
	}
	port=checkid->ceidbind(hostsocket);

	 acidbuf_id=checkid->sendtoemu(hostsocket,port);
	//checkid->sendtoemu(hostsocket, port, checkid->send2, sizeof(checkid->send2));
	//checkid->sendtoemu(hostsocket, port, checkid->send3, sizeof(checkid->send3));

	 if (!acidbuf_id) {

			 printf("无法获取eqemu包含id包\n");
	}
	 else
	 {
	 
	 checkid->DumpPacketHex(checkid->recv[acidbuf_id].pbuff, checkid->recv[acidbuf_id].pBuf_len);

	 for (i = 0; i <= acidbuf_id; i++)
	 {
		 delete[]checkid->recv[i].pbuff;
	 }

	 }
	closesocket(hostsocket);
	WSACleanup();
	getchar();
}