#ifndef __THREADING_H
#define __THREADING_H

#include "Build.h"

#include <stdio.h>
#include <string.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#else
 #include <unistd.h>
 #include <pthread.h>  //pthread
#endif


class Threading {
	CRITICAL_SECTION	mutex; 
	#ifdef __WIN32__RELEASE__
	HANDLE Thread;
	#else
		pthread_mutexattr_t mutexattr;
		pthread_t Thread;
	#endif
public:
	Threading();
	~Threading();
	void LockMutex(void);
	void UnLockMutex(void);
	int InitThread(void* func, void* parameter);
	int EndThread(void);
};

#endif