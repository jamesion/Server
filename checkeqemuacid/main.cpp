#include "CheckEmuAcid.h"


void main(string name, string password) 
{
	CheckEmuAcid *checkid = new CheckEmuAcid();
	int32 aclsid;
	string accountbuf;
	accountbuf = checkid->getaccount();
	aclsid=checkid->getemulsid(accountbuf,false);

	if (aclsid >= 0)
	{
		printf("acid:%d\n", aclsid);

		delete checkid;
	}


	if (aclsid == -1)
		printf("用户名或密码错误！\n");


	system("pause");

}