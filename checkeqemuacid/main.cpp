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
		delete checkid;
	}


	if (aclsid == -1)
		printf("�û������������%d\n",aclsid);


	system("pause");

}