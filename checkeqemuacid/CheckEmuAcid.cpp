#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "CheckEmuAcid.h"
#include "../openssl_x64/include/openssl/des.h"

#include <sstream>
#include <iomanip>




CheckEmuAcid::CheckEmuAcid()
{

}


CheckEmuAcid::~CheckEmuAcid()
{
	
}






//��ȡeqemu������ID
uint32 CheckEmuAcid::getemulsid()
{
	int i = 0, acidbuf_id = 0;
	uint32 aclsid = 0;
	SOCKET hostsocket = 0;
	unsigned short port;
	closesocket(hostsocket);
	WSACleanup();

	if (!(hostsocket = connountto()))
	{
		cout << "Socket����ʧ��!!" << endl;
		closesocket(hostsocket);
		return 0;
	}


	if (!(port = ceidbind(hostsocket)))
	{
		cout << "�˿ڰ�ʧ���˳�" << endl;
		return 0;
	};

	acidbuf_id = sendtoemu(hostsocket/*, port*/);

	if (!recv[acidbuf_id].pBuf_len) {

		printf("�޷���ȡeqemu����id��\n");
		return 0;
	}
	else
	{
		if (recv[acidbuf_id].pBuf_len == 98)
		{
		printf("acidbuf_id:%d\nrecv.len:%d\n", acidbuf_id,recv[acidbuf_id].pBuf_len);
		DumpPacketHex(recv[acidbuf_id].pbuff, recv[acidbuf_id].pBuf_len);
		
		aclsid=cryptoidbuff(acidbuf_id);
		}

		for (i = 0; i <= acidbuf_id; i++)
		{
			//printf("delete recv[%d]!\n",i);
			delete recv[i].pbuff;
			//printf("deleted!\n");
		}

	}

	WSACleanup();
	closesocket(hostsocket);


	//printf("acid:%d\n", aclsid);
	return aclsid;
}






//����socket
SOCKET CheckEmuAcid::connountto()
{
	int version_a = 2;                                        //low bit  
	int version_b = 2;                                        //high bit  

					    
	WORD versionRequest = MAKEWORD(version_a, version_b);     //makeword
	WSAData wsaData;
	int error;
	error = WSAStartup(versionRequest, &wsaData);

	if (error != 0) {
		printf("VersionRequest error!! ID:%d",error);
		return 0;
	}
//У��汾���Ƿ�Ϊ1.1  
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("����:WINSOCK�汾����!!\n");
		WSACleanup();
		return 0;
	}

 //����������socket����
	SOCKET socClient = socket(AF_INET, SOCK_DGRAM, 0);       

	
	printf("socket�����ɹ�.\n");
										
	return socClient;
}

//�������ݰ���emu
int CheckEmuAcid::sendtoemu(SOCKET socket /*unsigned short port*/)
{
	//����һ����������ַ��Ϣ����
	SOCKADDR_IN addrSrv;    
	SYSTEMTIME st = { 0 };
	SYSTEMTIME now_time = { 0 };

	ServerRecv_Struct *recvop = new ServerRecv_Struct;

	GetLocalTime(&st);

	int ret, i = 0,j=0, add_len = 0;

	add_len = sizeof(SOCKADDR_IN);

	/*struct timeval tv;
	tv.tv_sec = 10;
	tv.tv_usec = 0;
	if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(timeval)) < 0)
	{
		printf("socket option  SO_RCVTIMEO not support\n");
		return 0;

	}*/


	addrSrv.sin_addr.S_un.S_addr = inet_addr(HOST_IP);        //���÷�����IP
	addrSrv.sin_family = AF_INET;                             //����Э��  
	addrSrv.sin_port = htons(HOST_PORT);                      //���÷������˿�

	printf("���Է������ݰ���emu...\n");

	emusendto(clienup,sizeof(clienup), socket, addrSrv);


	while (true)
	{
		if (i > 10) break;
		ret = recvfrom(socket, (char*)recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&addrSrv, &add_len);
		if (ret > 0) {
			
			recv[i].pbuff = new uchar[ret];
			recv[i].pBuf_len = ret;

			//printf("i=%d\n", i);
			memcpy(recv[i].pbuff, recvbuf, recv[i].pBuf_len);

			cout << "���յ����ݱ�:" << " 			        size(" << ret << ")" << endl;
			DumpPacketHex(recv[i].pbuff, recv[i].pBuf_len);
			cout << endl;

			recvop = (ServerRecv_Struct*)recv[i].pbuff;
			printf("recvop=%d,%d\n",(int)recvop->op, recvop->para);
			switch (recvop->op)
			{
			
			case 2:
			{
				switch (recvop->para)
				{
				case 255:
				{
					account[40] = 0x85;
					account[41] = 0x78;
					sure[18] = 0xdd;
					sure[19] = 0x00;
				}
				case 0:
				{
					account[40] = 0x1c;
					account[41] = 0x9b;
					sure[18] = 0x93;
					sure[19] = 0x1f;

				}
				case 17:
				{
					account[40] = 0x24;
					account[41] = 0xf3;
					sure[18] = 0x0b;
					sure[19] = 0xda;

				}

				default:
				{
					emusendto(sure, sizeof(sure), socket, addrSrv);
					break;
				}
				}
			}
			case 9:
			{
				if (recvop->para == 2)
					emusendto(account, sizeof(account), socket, addrSrv);
				if (recvop->para == 3)
				{
					emusendto(end1, sizeof(end0), socket, addrSrv);
					emusendto(end1, sizeof(end1), socket, addrSrv);
					emusendto(end2, sizeof(end2), socket, addrSrv);
					emusendto(end2, sizeof(end3), socket, addrSrv);
					return i;
				}
				break;
			}

			default:
				break;
			}

			i++;
			GetLocalTime(&st);
		}

//���ճ�ʱ���

		GetLocalTime(&now_time);
		if ((now_time.wMinute - now_time.wMinute) >= 1) {
			now_time.wSecond = +(now_time.wMinute - now_time.wMinute) * 60;
		}

		
		if (now_time.wSecond - st.wSecond >10) {

			printf("���һ�λ�ȡ���ݰ�ʱ��:%02d...��ǰʱ��%02d....", st.wSecond, now_time.wSecond);
			printf("�������ݱ���ʱ�˳�����.\n");

			break;
			}


		}


	emusendto(end1, sizeof(end1), socket, addrSrv);
	emusendto(end2, sizeof(end2), socket, addrSrv);

		return i-1;

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
			return 0;
		}

		i++;
		//cout << "�󶨽��ն˿ڳɹ�,�˿�:" <<port<< endl;


	}


	cout << "port:" << port << endl;
	return port;
}


//��ʾʮ�����ƻ���

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


//�Խ��յ������ݰ�����

uint32 CheckEmuAcid::cryptoidbuff(int acidbuf_id)
{
	
	ServerAccepted_Struct *cryptost;
	
	char *decbuff = new char[80];
	char decrype_buff[80] = {0};


	cryptost = (ServerAccepted_Struct*)recv[acidbuf_id].pbuff;
	printf("cryptost->encrypt:\n");
	DumpPacketHex((uchar*)cryptost->encrypt, 80);

	
	auto rc = eqcrypt_block((char*)cryptost->encrypt, 80, decrype_buff,0);
	
	
	printf("des_crype_buff:\n");
	 DumpPacketHex((uchar*)decrype_buff, 80);

	decrypt = (ServerFailedAttempts_Struct*)decrype_buff;
	//printf("acid:%d\n", decrypt->lsid);
	
	
	return  decrypt->lsid;

}








int CheckEmuAcid::emusendto(unsigned char* send, int Size,SOCKET socket, SOCKADDR_IN addrSrv)
{
	printf("���Է������ݰ���emu...\n");

	sendto(socket, (char*)send, Size, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));

	cout << "�������ݱ�:" << "        size(" <<  Size  << ")" << endl;
	DumpPacketHex((uchar *)send, Size);
	return 0;
}
