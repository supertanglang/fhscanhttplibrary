#ifndef __COOKIEHANDLING_H
#define __COOKIEHANDLING_H

#include "Build.h"
#include "Tree.h"
#include "Threading.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef __WIN32__RELEASE__
 #include <windows.h>
#else
 #include <unistd.h>
 #include <pthread.h>  //pthread
#endif

#define COOKIETIMEFORMAT  "%a, %d-%b-%Y %H:%M:%S GMT" /* time formats in cookie headers */
#define COOKIETIMEFORMAT2 "%a, %d-%b-%y %H:%M:%S GMT" /* some idiotic websites send the year without the century */
#define GetDataWithoutSpaces(data) \
	while (*data==' ') data++;     \
	while (data[strlen(data)-1]==' ') data[strlen(data)-1]='\0'

#define IS_PATH(a)		(strcmp(a,"path")==0)
#define IS_EXPIRES(a)	(strcmp(a,"expires")==0)
#define IS_DOMAIN(a)   	(strcmp(a,"domain")==0)
#define IS_MAXAGE(a)    (strcmp(a,"max-age")==0)
#define IS_VERSION(a)   (strcmp(a,"version")==0)

#define IS_HTTPONLY(a)    (strcmp(a,"HttpOnly")==0)
#define IS_HTTPONLY2(a)    (strcmp(a,"httponly")==0)

#define IS_SECURE(a)    (strcmp(a,"secure")==0)
/* Sanity checks.  These are important, otherwise it is possible for
mailcious attackers to destroy important cookie information and/or
violate your privacy.  */


#define REQUIRE_DIGITS(p) do {                  \
	if (!ISDIGIT (*p))                            \
	return 0;                                   \
	for (++p; ISDIGIT (*p); p++)                  \
	;                                           \
} while (0)

#define REQUIRE_DOT(p) do {                     \
	if (*p++ != '.')                              \
	return 0;                                   \
} while (0)

/* Check whether ADDR matches <digits>.<digits>.<digits>.<digits>.

We don't want to call network functions like inet_addr() because all
we need is a check, preferrably one that is small, fast, and
well-defined.  */




class Cookie
{
	char *lpCookieName;
	char *lpCookieValue;
	time_t expire;
	char *path;
	char *domain;
	BOOL secure;
	BOOL httponly;
public:
	Cookie();
	Cookie(char *cName,char *cValue,time_t cExpire,char *cPath,char *cDomain, int cSecure, int cHttponly );
	~Cookie();
	int MatchCookie(char *lppath,char *lpdomain,char *lpCookieName, int securevalue);
	void SetDate(time_t cExpire);
	time_t GetDate(void) { return expire;}
	int path_matches (const char *RequestedPath);
	char *GetCookieName(void) { return (lpCookieName); }
	char *GetCookieValue(void) { return (lpCookieValue); }
	char *GetCookiePath(void)  { return (path); }
	char *GetCookieDomain(void) { return domain; }
	BOOL IsSecure(void) { return secure; }
	void SetValue(char *cValue);
};

/***********************************************************************/
struct CookieList
{
	//class Threading *lock;
	int nCookies;
	class Cookie **CookieElement;
};

#define MAX_COOKIES_PER_DOMAIN 1000

class CookieStatus 
{
	bTree *DomainList;
	int nDomains;
	class Threading lock;

	int RemoveCookieFromList(struct CookieList *List,char *path,char *name, char *lpDomain);
	//void InsertCookieToList(struct CookieList *List,char *path, char *name, char *value, int secure, int HttpOnly);
	int numeric_address_p (const char *addr);
	int check_domain_match (const char *cookie_domain, const char *host);
	BOOL cookie_expired (time_t CookieExpireTime);

public:
	CookieStatus();
	BOOL ExtractDate(char *lpdate, time_t *expires);
	int ParseCookieData(char *lpCookieData, const char *lpPath, const char *lpDomain);
	char *ReturnCookieHeaderFor(const char *lpDomain,const char *path,int CookieOverSSL);

	int CookieAlreadyExist(struct CookieList *List,char *path, char *domain, char *name, int secure );
	~CookieStatus();

};


#endif
