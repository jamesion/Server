#include "CheckEmuAcid.h"


void main(string name, string password) 
{
	CheckEmuAcid *checkid = new CheckEmuAcid();
	uint32 aclsid;
	
	aclsid=checkid->getemulsid();

	if (aclsid)
	{
		printf("acid:%d\n", aclsid);

		delete checkid;
	}


	if (aclsid == -1)
		printf("用户名或密码错误！\n");


	system("pause");

}