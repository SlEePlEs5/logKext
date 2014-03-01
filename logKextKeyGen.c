#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <openssl/rand.h>
#include "logKextKeyGen.h"

void removeKey()
{
	SecKeychainRef sysChain;
	OSStatus secRes = SecKeychainOpen("/Library/Keychains/System.keychain", &sysChain);
	if (secRes)
	{
		printf("Couldn't get system keychain: %d\n",secRes);
		return;
	}

	SecKeychainItemRef itemRef=NULL;
	secRes = SecKeychainFindGenericPassword(sysChain, strlen("logKextPassKey"), "logKextPassKey", 0, NULL, NULL, NULL, &itemRef);
	if (secRes && secRes != errSecItemNotFound) {
		printf("Error: couldn't find item: %d\n",secRes);
		return;
	}
	else if (secRes == errSecItemNotFound) {
		printf("Error: couldn't find passkey\n");
		return;
	}
	else
		printf("Successfully found item\n");

	secRes = SecKeychainItemDelete(itemRef);
	if (secRes)
		printf("Couldn't delete item: %d\n",secRes);
	else
		printf("Deleted item\n");
}

SecAccessRef getAccessRef()
{
	SecTrustedApplicationRef appRefs[3];
	// corresponds to self
	OSStatus secRes = SecTrustedApplicationCreateFromPath(NULL, &appRefs[0]);
	if (secRes)
	{
		printf("Error: couldn't create trusted app from keygen path: %d\n",secRes);
		return NULL;
	}
	secRes = SecTrustedApplicationCreateFromPath(DAEMON_PATH, &appRefs[1]);
	if (secRes)
	{
		printf("Error: couldn't create trusted app from daemon path: %d\n",secRes);
		return NULL;
	}
	secRes = SecTrustedApplicationCreateFromPath(CLIENT_PATH, &appRefs[2]);
	if (secRes)
	{
		printf("Error: couldn't create trusted app from client path: %d\n",secRes);
		return NULL;
	}
	CFArrayRef trustedList = CFArrayCreate(NULL, (void*)appRefs, sizeof(appRefs)/sizeof(*appRefs), NULL);
	SecAccessRef accessRef;
	secRes = SecAccessCreate(CFSTR("logKextPassKey"), trustedList, &accessRef);
	if (secRes)
	{
		printf("Error: couldn't create secAccess %d\n",secRes);
		return NULL;
	}
	return accessRef;
}

void generateKey()
{
	SecKeychainRef sysChain;
	OSStatus secRes = SecKeychainOpen("/Library/Keychains/System.keychain", &sysChain);
	if (secRes)
	{
		printf("Couldn't get system keychain: %d\n",secRes);
		return;
	}

	SecAccessRef accessRef =  getAccessRef();
	if (accessRef==NULL)
		return;

	SecKeychainItemRef itemRef=NULL;	
	char *passData;
	UInt32 passLen=0;
	secRes = SecKeychainFindGenericPassword(sysChain, strlen("logKextPassKey"), "logKextPassKey", 0, NULL, NULL, NULL, &itemRef);
	if (secRes != errSecItemNotFound)
	{
		printf("Warning: item already exists\n");

		secRes = SecKeychainItemCopyContent(itemRef, NULL, NULL, &passLen, (void**)&passData);
		if (secRes)
		{
			printf("Error: Unable to copy keychain data: %d\n",secRes);
			return;
		}		
		secRes = SecKeychainItemDelete(itemRef);
		if (secRes)
		{
			printf("Error: Unable to delete original keychain item: %d\n",secRes);
			return;
		}				
	}
	else if (secRes == errSecItemNotFound)
	{
		passLen=16;
		passData = malloc(passLen);
		RAND_bytes((unsigned char*)passData, passLen);
	}
	else
	{
		printf("Error accessing keychain: %d\n",secRes);
		return;
	}

	SecKeychainAttribute attrs[] = {
		{ kSecLabelItemAttr, strlen("logKextPassKey"), "logKextPassKey" },
		{ kSecServiceItemAttr, strlen("logKextPassKey"), "logKextPassKey" }
	};	
	SecKeychainAttributeList attributes = { sizeof(attrs) / sizeof(attrs[0]), attrs };
	
	secRes = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &attributes, passLen, passData, sysChain, accessRef, &itemRef);
	if (secRes)
		printf("Error creating keychain item: %d\n",secRes);
}

int main (int argc, const char * argv[]) {

	if (argc>1 && !strcmp(argv[1], "remove"))
		removeKey();
	else
		generateKey();
	
    return 0;
}
