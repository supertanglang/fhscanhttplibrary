#ifndef _DIGEST_
#define _DIGEST_
//#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <string.h>
#ifdef __WIN32__RELEASE__
#include <windows.h>
#endif

char *CreateDigestAuth(char *AuthenticationHeader, const char *lpUsername, const char *lpPassword, const char *method,const char *uri, int counter);

#endif

