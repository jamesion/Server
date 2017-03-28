#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "CheckEmuAcid.h"

#include <sstream>
#include <iomanip>


CheckEmuAcid::CheckEmuAcid()
{

}


CheckEmuAcid::~CheckEmuAcid()
{
	
}

//����socket
SOCKET CheckEmuAcid::connountto()
{
	int version_a = 1;                                        //low bit  
	int version_b = 1;                                        //high bit  

					    
	WORD versionRequest = MAKEWORD(version_a, version_b);     //makeword
	WSAData wsaData;
	int error;
	error = WSAStartup(versionRequest, &wsaData);

	if (error != 0) {
		printf("VersionRequest error!! ID:%d",error);
		return 0;
	}
//У��汾���Ƿ�Ϊ1.1  
	if (LOBYTE(wsaData.wVersion) != 1 || HIBYTE(wsaData.wVersion) != 1)
	{
		printf("����:WINSOCK�汾����!!");
		WSACleanup();
		return 0;
	}


	SOCKET socClient = socket(AF_INET, SOCK_DGRAM, 0);        //����������socket����

	
	printf("socket�����ɹ�.\n");
										
	return socClient;
}

//�������ݰ���emu
unsigned char * CheckEmuAcid::sendtoemu(SOCKET socket, unsigned short port,unsigned char* sendbuff,int size)
{
	
	SOCKADDR_IN addrSrv;    //����һ����������ַ��Ϣ����
	RecvBuff recv[5] = { 0 };
	uchar recvbuf[255] = { 0 };

	

	addrSrv.sin_addr.S_un.S_addr = inet_addr(HOST_IP);        //���÷�����IP
	addrSrv.sin_family = AF_INET;                             //����Э��  
	addrSrv.sin_port = htons(HOST_PORT);                      //���÷������˿�

	printf("���Է������ݰ���emu...");

	sendto(socket,(char*)sendbuff,(int)size,0,(SOCKADDR*)&addrSrv,sizeof(SOCKADDR));
	//sendto(socket, (char *)send2, 20, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	//sendto (char *)send3, 42, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	
	cout << "�������ݱ�:"<<"        size(" << size << ")" << endl;
	DumpPacketHex((uchar *)sendbuff, size);

	struct timeval tv;
	int ret,i=0,j=0;
	tv.tv_sec = 10;
	tv.tv_usec = 0;

	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0) 
	{
		    printf("socket option  SO_RCVTIMEO not support\n");
		    return 0;

	}
	while ((ret = recvfrom(socket, (char*)recvbuf, sizeof(recvbuf), 0, NULL, NULL))>=0)
	{
		recv[i].pbuff = new uchar[ret] ;
		recv[i].pBuf_len = ret;

		cout << "���յ����ݱ�:" << " 			        size(" << ret << ")" << endl;
		cout << "δת��:" << endl;
		DumpPacketHex(recvbuf, sizeof(recvbuf));
		
		cout << endl;
		memcpy(recv[i].pbuff, recvbuf, recv[i].pBuf_len);
		//i++;
		//Sleep(1000);
	
		cout << "ת����:" << " 			        size(" << recv[i].pBuf_len << ")  " << ret << endl;
		DumpPacketHex(recv[i].pbuff, recv[i].pBuf_len);
		cout << endl;

		i++;

		}




		if (ret == EWOULDBLOCK || ret == EAGAIN) {
			        printf("recvfrom timeout\n");
					
		}
		else { 	
			if (ret == -1)
				printf("�޽��հ�\n");

			else
				printf("recvfrom err:%d\n\n", ret);
			}
		

	

	

	

	WSACleanup();
	
	delete[]recv->pbuff;
	
		//Sleep(10000);
}

//��ʾʮ�����ƻ���
void CheckEmuAcid::dumpbuffhex(unsigned char *buff, int size)
{
	int i=0;
	int j = 0;

		while (i <= size-1)
	{
		if (buff[i] < 0x10)
		{
			std::cout << "0x0" << hex << static_cast <int>(buff[i]) << " ";
		}
		else
		{
			std::cout << "0x" << hex << static_cast <int>(buff[i]) << " ";
		}
		if (!((i + 1) % 10))
		{
			j = j + 10;

			cout << dec << "   " << j << endl;
		}
		i++;
	};
		cout << dec << endl;
}


unsigned short CheckEmuAcid::ceidbind(SOCKET socket)
{
	int i = 0;
	SOCKADDR_IN serverin;
	EQEmu::Random random;
	unsigned short port = random.Int(50000, 60000);

	serverin.sin_family = AF_INET;
	serverin.sin_port = htons(port);             //���Ͷ�ʹ�õķ��Ͷ˿ڣ����Ը�����Ҫ����
	serverin.sin_addr.s_addr = htonl(INADDR_ANY);


	while ((bind(socket, (SOCKADDR FAR *)&serverin, sizeof(serverin)) != 0) && (i <= 100))
	{
		port = random.Int(50000, 60000);
		serverin.sin_port= htons(port);

		if (i == 100)
		{
			cout << "�󶨽��ն˿�ʧ��,Ӧ�ý��˳�." << endl;
			return -1;
		}

		i++;
		cout << "�󶨽��ն˿ڳɹ�,�˿�:" <<port<< endl;

		//return port;
	}


	cout << "port:" << port << endl;
	return port;
}

void CheckEmuAcid::DumpPacketHex(const uchar * buf, uint32 size, uint32 cols, uint32 skip)
{
	if (size == 0 || size > 39565)
		return;
	// Output as HEX
	char output[4];
	int j = 0;
	auto ascii = new char[cols + 1];
	memset(ascii, 0, cols + 1);
	uint32 i;
	for (i = skip; i<size; i++)
	{
		if ((i - skip) % cols == 0) {
			if (i != skip)
				std::cout << " | " << ascii << std::endl;
			std::cout << std::setw(4) << std::setfill(' ') << i - skip << ": ";
			memset(ascii, 0, cols + 1);
			j = 0;
		}
		else if ((i - skip) % (cols / 2) == 0) {
			std::cout << "- ";
		}
		sprintf(output, "%02X ", (unsigned char)buf[i]);
		std::cout << output;

		if (buf[i] >= 32 && buf[i] < 127) {
			ascii[j++] = buf[i];
		}
		else {
			ascii[j++] = '.';
		}
		//		std::cout << std::setfill(0) << std::setw(2) << std::hex << (int)buf[i] << " "; // unknown intent [CODEBUG]
	}
	uint32 k = ((i - skip) - 1) % cols;
	if (k < 8)
		std::cout << "  ";
	for (uint32 h = k + 1; h < cols; h++) {
		std::cout << "   ";
	}
	std::cout << " | " << ascii << std::endl;
	safe_delete_array(ascii);

}

std::string CheckEmuAcid::DumpPacketHexToString(const uchar * buf, uint32 size, uint32 cols, uint32 skip)
{
	std::ostringstream out;
	if (size == 0 || size > 39565)
		return "";

	out << "\n";

	// Output as HEX
	char output[4];
	int j = 0;
	auto ascii = new char[cols + 1];
	memset(ascii, 0, cols + 1);
	uint32 i;
	for (i = skip; i < size; i++)
	{
		if ((i - skip) % cols == 0) {
			if (i != skip)
				out << " | " << ascii << std::endl;
			out << std::setw(4) << std::setfill(' ') << i - skip << ": ";
			memset(ascii, 0, cols + 1);
			j = 0;
		}
		else if ((i - skip) % (cols / 2) == 0) {
			out << "- ";
		}
		sprintf(output, "%02X ", (unsigned char)buf[i]);
		out << output;

		if (buf[i] >= 32 && buf[i] < 127) {
			ascii[j++] = buf[i];
		}
		else {
			ascii[j++] = '.';
		}
		//		std::cout << std::setfill(0) << std::setw(2) << std::hex << (int)buf[i] << " "; // unknown intent [CODEBUG]
	}
	uint32 k = ((i - skip) - 1) % cols;
	if (k < 8)
		out << "  ";
	for (uint32 h = k + 1; h < cols; h++) {
		out << "   ";
	}
	out << " | " << ascii << std::endl;
	safe_delete_array(ascii);

	return out.str();
}


void CheckEmuAcid::emulisentfrom(SOCKET socket, unsigned short port)
{
	bool reluf = true;
	/*while (reluf)
	{
		if(revcbuf)
	}*/
}

