#include "CheckEmuAcid.h"


void main(string name, string password) 
{
	CheckEmuAcid *checkid = new CheckEmuAcid();
	uint32 aclsid;
	
	aclsid=checkid->getemulsid();

	if(aclsid)
	printf("acid:%d\n", aclsid);

	delete checkid;

	getchar();

}