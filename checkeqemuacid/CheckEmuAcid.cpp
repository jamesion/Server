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
int CheckEmuAcid::sendtoemu(SOCKET socket, unsigned short port)
{
	
	SOCKADDR_IN addrSrv;    //����һ����������ַ��Ϣ����
	
	

	int ret, i = 0,j=0, add_len = 0;

	add_len = sizeof(SOCKADDR_IN);

	struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval)) < 0)
	{
		printf("socket option  SO_RCVTIMEO not support\n");
		return 0;

	}


	addrSrv.sin_addr.S_un.S_addr = inet_addr(HOST_IP);        //���÷�����IP
	addrSrv.sin_family = AF_INET;                             //����Э��  
	addrSrv.sin_port = htons(HOST_PORT);                      //���÷������˿�

	printf("���Է������ݰ���emu...\n");

	sendto(socket,(char*)send1, sizeof(send1),0,(SOCKADDR*)&addrSrv,sizeof(SOCKADDR));
	//sendto(socket, (char *)send2, 20, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	//sendto (char *)send3, 42, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	
	cout << "�������ݱ�:"<<"        size(" << sizeof(send1) << ")" << endl;
	DumpPacketHex((uchar *)send1, sizeof(send1));

	while (true)
	{
		ret = recvfrom(socket, (char*)recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&addrSrv, &add_len);
		if (ret < 0) {
			if (ret == EWOULDBLOCK || ret == EAGAIN) {
			printf("recvfrom timeout\n");
			break;

		
			}
			else 
				if (ret == -1) {
				//printf("�޽��հ�,������:%d\n", WSAGetLastError());
				//WsaGetlasterror����;
					}

					
				else {
				printf("recvfrom err:%d\n\n", ret);
				}
				}

			
		else {
		
		recv[i].pbuff = new uchar[ret] ;
		recv[i].pBuf_len = ret;

		
		memcpy(recv[i].pbuff, recvbuf, recv[i].pBuf_len);
	
		cout << "���յ����ݱ�:" << " 			        size(" << ret << ")" << endl;
		DumpPacketHex(recv[i].pbuff, recv[i].pBuf_len);
		cout << endl;

		switch (ret)
		{
		case 21:
		{
			printf("���Է������ݰ���emu...\n");

			sendto(socket, (char*)send2, sizeof(send2), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));

			cout << "�������ݱ�:" << "        size(" << sizeof(send2) << ")" << endl;
			DumpPacketHex((uchar *)send2, sizeof(send2));
			break;
		}
		case 25:
		{
			printf("���Է������ݰ���emu...\n");

			sendto(socket, (char*)send3, sizeof(send3), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));

			cout << "�������ݱ�:" << "        size(" << sizeof(send3) << ")" << endl;
			DumpPacketHex((uchar *)send3, sizeof(send3));
			break;
		}
		case 98:
		{
			printf("eqemuacid �ձ��ɹ�...\n");


			//acidbuf->pbuff = new uchar[ret];
			//acidbuf = recv;
			WSACleanup();

			

			return i;

			

			break;
		}


		default:
			break;
		}
		i++;
		}
		j++;
		//printf("j:%d.", j);
		if (j >= 500) {
			printf("end");
			return 0;
			}
		}
	return i;

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

