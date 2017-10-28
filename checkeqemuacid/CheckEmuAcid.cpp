#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "CheckEmuAcid.h"
#include <openssl/des.h>

#include <sstream>
#include <iomanip>
#include <iostream>
#include <string>
 
CheckEmuAcid::CheckEmuAcid()
{
}

CheckEmuAcid::~CheckEmuAcid()
{	

}

//��ȡeqemu������ID
int32 CheckEmuAcid::getemulsid(string accountbuf,bool needcrypto)
{
	int i = 0, acidbuf_id = 0;
	uint32 aclsid = 0;
	SOCKET hostsocket = 0;
//	string accountbuf;
	closesocket(hostsocket);
//	WSACleanup();

	if (needcrypto)
	{
		auto r = eqcrypt_block(accountbuf.c_str(), accountbuf.size(), (char*)accountbuf.c_str(), 1);
		if (r == nullptr) {
			printf("Failed to decrypt eqcrypt block");
			return 0;
		}
	}

	if (!(hostsocket = connountto()))
	{
		cout << "Socket����ʧ��!!" << endl;
		closesocket(hostsocket);
		return -1;
	}

//	accountbuf=getaccount();
	cout << "accout size:" << accountbuf.size() << endl;
	DumpPacketHex((uchar *)accountbuf.c_str(), (uint32)accountbuf.size());

	acidbuf_id = sendtoemu(hostsocket,accountbuf);

	if (recv[acidbuf_id].pBuf_len <= 0) {

		printf("�޷���ȡeqemu����id��\n");
		for (i = 0; i <= acidbuf_id; i++)
		{
			//printf("delete recv[%d]!\n",i);
			delete recv[i].pbuff;
			//printf("deleted!\n");
		}
		return -1;
	}
	else
	{
		if (recv[acidbuf_id].getlsid)
		{
		printf("acidbuf_id:%d\nrecv.len:%d,getlsid:%d\n", acidbuf_id,recv[acidbuf_id].pBuf_len, recv[acidbuf_id].getlsid);
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

	shutdown(hostsocket, SD_BOTH);
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
int CheckEmuAcid::sendtoemu(SOCKET socket ,string accountbuff)
{
	//����һ����������ַ��Ϣ����
	SOCKADDR_IN addrSrv;
	SYSTEMTIME st = { 0 };
	SYSTEMTIME now_time = { 0 };
//	SYSTEMTIME now_timeout = { 0 }, st_timeout = { 0 };
	int times=0;
//	GetLocalTime(&st_timeout);

	string outbuffer = "";
	string pOut;

	//outbuffer.resize(accountbuff.size()+26, NULL);
	
	ServerRecv_Struct *recvop = new ServerRecv_Struct;
	GetLocalTime(&st);
	recvop->op = 0;
	int ret, i = -1, j = 0, add_len = 0, actimes = 0;
	uint32 key = 0;
	uint32 size;
	add_len = sizeof(SOCKADDR_IN);

	

	addrSrv.sin_addr.S_un.S_addr = inet_addr(HOST_IP);        //���÷�����IP
	addrSrv.sin_family = AF_INET;                             //����Э��  
	addrSrv.sin_port = htons(HOST_PORT);        //���÷������˿�

	struct timeval tv_out;
	tv_out.tv_sec = 10;//�ȴ�10��
	tv_out.tv_usec = 0;
	setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv_out, sizeof(tv_out));


	outbuffer.append((char*)accounthead, sizeof(accounthead));
	itoa(accountbuff.size() , (char*)&outbuffer[7], 16);
	outbuffer.append((char*)account,sizeof(account));
	outbuffer += accountbuff;
//	emusendto(clienup,sizeof(clienup), socket, addrSrv);

//	GetLocalTime(&now_time);
	if ((now_time.wMinute - st.wMinute) >= 1) {
		now_time.wSecond += (now_time.wMinute - st.wMinute) * 60;
	}

	while (true)
	{
		int intcrc,htoncrc;
		if (i >= 20)
		{
			recv[i].pBuf_len = 0;
			recv[i].pbuff = new uchar;
			recv[i].getlsid = false;
			break;
		}
		
		//cout << "bigin recvfrom ret:" << endl;
		ret = recvfrom(socket, (char*)recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&addrSrv, &add_len);
		cout << "recvfrom ret:" << ret << endl;

		if (ret > 0) {

			i++;
			recv[i].pbuff = new uchar[ret];
			recv[i].pBuf_len = ret;

			memcpy(recv[i].pbuff, recvbuf, recv[i].pBuf_len);

			cout << "���յ����ݱ�:" << " 			        size(" << ret << ")" << endl;
			DumpPacketHex(recv[i].pbuff, recv[i].pBuf_len);
			cout << endl;

			recvop = (ServerRecv_Struct*)recv[i].pbuff;
			printf("recvop=%d\n", (int)recvop->op);

			GetLocalTime(&st);

		}
			switch (recvop->op)
			{
			case 0:
				emusendto((char*)clienup, sizeof(clienup), socket, addrSrv);
				break;

			case 2:

				key = EQ::Net::NetworkToHost(recvop->para);

				pOut.clear();
				pOut.append((char*)sure,sizeof(sure));
				intcrc = EQ::Crc32(pOut.c_str(), (int)pOut.size(), key) & 0xffff;

				pOut += intcrc >> 8;
				pOut += intcrc;
				printf("intcrc:%d,key:%d\n", intcrc, key);
				emusendto((char*)pOut.c_str(), (int)pOut.size(), socket, addrSrv);
			break;
			
			case 9:
			
				if (recvop->para == 2)
				{

					pOut.clear();
					pOut.append((char*)account, sizeof(account));
					pOut += accountbuff;

					intcrc = EQ::Crc32(pOut.c_str(), (int)pOut.size(), key) & 0xffff;

					pOut += intcrc >> 8;
					pOut += intcrc;
					emusendto((char*)pOut.c_str(), (int)pOut.size(), socket, addrSrv);


				}
				if (recvop->para == 3)
				{
					emusendto((char*)end0, sizeof(end0), socket, addrSrv);
					emusendto((char*)end1, sizeof(end1), socket, addrSrv);
					emusendto((char*)end2, sizeof(end2), socket, addrSrv);
					emusendto((char*)end3, sizeof(end3), socket, addrSrv);
					recv[i].getlsid = true;
					return i;
				}
				break;
			
			case 3:
					pOut.clear();
					pOut = outbuffer;
					intcrc = EQ::Crc32(pOut.c_str(), (int)pOut.size(), key) & 0xffff;
					pOut += intcrc >> 8;
					pOut += intcrc;

					emusendto((char*)pOut.c_str(), (int)pOut.size(), socket, addrSrv);
					//emusendto((char*)outbuffer.c_str(), (int)outbuffer.size(), socket, addrSrv);
				break;
			
			default:
				break;
			}

			

		

//���ճ�ʱ���

		GetLocalTime(&now_time);
		if ((now_time.wMinute - st.wMinute) >= 1) {
			now_time.wSecond += (now_time.wMinute - st.wMinute) * 60;
		}

		if ((now_time.wSecond - st.wSecond) >=10) {

			printf("���һ�λ�ȡ���ݰ�ʱ��:%02d...��ǰʱ��%02d....", st.wSecond, now_time.wSecond);
			printf("�������ݱ���ʱ�˳�����.\n");

				recv[i].pBuf_len = 0;
				recv[i].pbuff = new uchar;
				recv[i].getlsid = false;
		
			break;
			}


			Sleep(1000);
		
		}


		emusendto((char*)end0, sizeof(end0), socket, addrSrv);
		emusendto((char*)end1, sizeof(end1), socket, addrSrv);
		emusendto((char*)end2, sizeof(end2), socket, addrSrv);
		emusendto((char*)end3, sizeof(end3), socket, addrSrv);
	printf("����i:%d\n", i);
		return i;

	} 



/*unsigned short CheckEmuAcid::ceidbind(SOCKET socket)
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
	
}*/


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

string CheckEmuAcid::getaccount(string account)
{
	string  pbuff, accountbuf;

	int newsize = 0;
	if (account == "")
	{
		cout << "UserName is NULL!" << endl;
		return 0;
	}

		if (account.size() > 160)
		{
			cout << "Account size must less that 160 byte!" << endl;
		}
		pbuff = account;

	newsize = (int)pbuff.size() / 8;

	if (pbuff.size() % 8)
		newsize++;
	pbuff.resize(newsize * 8);
	accountbuf.resize(newsize * 8);


	auto r = eqcrypt_block(pbuff.c_str(), pbuff.size(), (char*)accountbuf.c_str(), 1);
	if (r == nullptr) {
		printf("Failed to decrypt eqcrypt block");
		return 0;
	}

	return accountbuf;
	return string();
}








int CheckEmuAcid::emusendto(char* send, int Size,SOCKET socket, SOCKADDR_IN addrSrv)
{
	printf("���Է������ݰ���emu...\n");

	sendto(socket, send, Size, 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));


	cout << "�������ݱ�:" << "        size(" <<  Size  << ")" << endl;
	DumpPacketHex((uchar *)send, Size);
	return 0;
}


string CheckEmuAcid::getaccount()
{
	char fn = 0x00;
	bool upass = false;
	string username,passwd,pbuff, accountbuf;

	int newsize = 0;
	while(!upass)
	{
		cout << "UserName:";
		cin >> username;

		cout << "Password:";
		cin >> passwd;

		if (username.size() < 80 && passwd.size() < 80)		
			upass = true;

		else
		cout << "UserName or Password must less that 80 byte!" << endl;
	}
	pbuff = username + fn + passwd;
	
	newsize=(int)pbuff.size() / 8;
	
	if (pbuff.size() % 8)
		newsize++;
	pbuff.resize(newsize *8);
	accountbuf.resize(newsize * 8);


	auto r = eqcrypt_block(pbuff.c_str(), pbuff.size(),(char*)accountbuf.c_str(), 1);
	if (r == nullptr) {
		printf("Failed to decrypt eqcrypt block");
		return 0;
	}

	return accountbuf;
}
