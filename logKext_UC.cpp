/*
	logKext_UC.cpp
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

#include "logKext.h"

#define super IOUserClient
OSDefineMetaClassAndStructors( logKextUserClient, IOUserClient );

bool logKextUserClient::initWithTask( task_t owningTask,
                                        void * securityID,
                                        UInt32 type,
                                        OSDictionary * properties )
{
	if (clientHasPrivilege(owningTask, kIOClientPrivilegeAdministrator)!=kIOReturnSuccess)
	{
		IOLog( "logKextUserClient::Error: unprivileged task attempted to init\n");	
		return false;
	}

	#ifdef LK_DEBUG
		IOLog("logKextUserClient::initWithTask(type %ld)\n", type);
	#endif
	
	if (!super::initWithTask(owningTask, securityID, type))
        return false;

    if (!owningTask)
		return false;
	
    fTask = owningTask;	// remember who instantiated us
	fProvider = NULL;
	
    return true;
}


bool logKextUserClient::start( IOService* provider )
{    
	#ifdef LK_DEBUG
		IOLog( "logKextUserClient::start\n" );
	#endif
    
    if( !super::start( provider ) )
        return false;
    
    // see if it's the correct class and remember it at the same time
    fProvider = OSDynamicCast( com_fsb_iokit_logKext, provider );
    if( !fProvider )
        return false;
		
	fProvider->activate();	// call activate on kext to hook keyboards

	return true;
}

void logKextUserClient::stop( IOService* provider )
{
	#ifdef LK_DEBUG
		IOLog( "logKextUserClient::stop\n" );
	#endif

    super::stop( provider );
}


IOReturn logKextUserClient::clientClose( void )
{
	#ifdef LK_DEBUG
		IOLog( "logKextUserClient::clientClose\n" );
	#endif
    
	fProvider->deactivate();	// call deactivate on kext to unhook keyboards
	
    fTask = NULL;
    fProvider = NULL;
    terminate();
    
    return kIOReturnSuccess;

}

IOExternalMethod* logKextUserClient::getTargetAndMethodForIndex(IOService** targetP, UInt32 index )
{
	*targetP = fProvider;	// driver is target of all our external methods
    
    // validate index and return the appropriate IOExternalMethod
    if( index < kNumlogKextMethods )
        return (IOExternalMethod*) &externalMethods[index];
    else
        return NULL;
}
