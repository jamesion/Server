#include "CheckEmuAcid.h"


void main(string IP, string name, string password) 
{
	CheckEmuAcid *checkid = new CheckEmuAcid();
	SOCKET hostsocket = 0;
	unsigned short port;
	closesocket(hostsocket);
	WSACleanup();

	if (!(hostsocket= checkid->connountto()))
	{
		cout <<"Socket½¨Á¢Ê§°Ü!!"<<endl;
	}
	port=checkid->ceidbind(hostsocket);

	checkid->sendtoemu(hostsocket,port,checkid->send1,sizeof(checkid->send1));
	checkid->sendtoemu(hostsocket, port, checkid->send2, sizeof(checkid->send2));
	checkid->sendtoemu(hostsocket, port, checkid->send3, sizeof(checkid->send3));

	closesocket(hostsocket);
	WSACleanup();
	getchar();
}