#include "Threading.h"


/*******************************************************************************************************/
Threading::Threading()
{
#ifdef __WIN32__RELEASE__
   InitializeCriticalSection(&mutex);
#else
   pthread_mutexattr_settype(&mutexattr,PTHREAD_MUTEX_RECURSIVE); // Set the mutex as recursive
   pthread_mutex_init((pthread_mutex_t*)&mutex, &mutexattr);  // create the mutex with the attributes set
   pthread_mutexattr_destroy(&mutexattr);
#endif
   Thread = 0;
}
/*******************************************************************************************************/
Threading::~Threading()
{
#ifdef __WIN32__RELEASE__
	DeleteCriticalSection((CRITICAL_SECTION*)&mutex);
#else
	pthread_mutex_destroy ((pthread_mutex_t*)&mutex);
#endif
}
/*******************************************************************************************************/
void Threading::LockMutex(void)
{
	#ifdef __WIN32__RELEASE__
		EnterCriticalSection((CRITICAL_SECTION*)&mutex);
	#else
		pthread_mutex_lock ((pthread_mutex_t*)&mutex);
	#endif
}
/*******************************************************************************************************/
void Threading::UnLockMutex(void)
{
	#ifdef __WIN32__RELEASE__
	   LeaveCriticalSection((CRITICAL_SECTION*)&mutex);
	#else
	   pthread_mutex_unlock ((pthread_mutex_t*)&mutex);
	#endif
}
/*******************************************************************************************************/
int Threading::InitThread(void* func, void* parameter)
{
#ifdef __WIN32__RELEASE__
	DWORD dwThread;
	Thread=CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) func, (LPVOID) parameter, 0, &dwThread);
#else
	void* (*foo)(void*) = (void*(*)(void*))func;
	pthread_create(&Thread, NULL, foo, (void *)parameter);
#endif
	return(1);
}
/*******************************************************************************************************/
int Threading::EndThread(void)
{
	#ifdef __WIN32__RELEASE__
		TerminateThread(Thread,0);
	#else
		pthread_cancel(Thread);
	#endif
	return(1);
}
/*******************************************************************************************************/