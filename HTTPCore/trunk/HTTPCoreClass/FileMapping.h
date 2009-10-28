/** \file FileMapping.h
 * Fast HTTP Auth Scanner - HTTP Engine v1.3.
 * This include file contains all needed information to manage File mappings.
 * \author Andres Tarasco Acuna - http://www.tarasco.org
 */
#ifndef __FILEMAPPING_H__
#define __FILEMAPPING_H__

#include "Build.h"
#ifdef __WIN32__RELEASE__
 #include <sys/timeb.h>
 #include <process.h>
 #include <time.h>
 #include <windows.h>
#else
 #include <stdlib.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <pthread.h>
 #include <ctype.h>
 #include <time.h>
 #include <sys/timeb.h>
#endif


class HTTPIOMapping
{
   int			   assigned;
   char			  *BufferedPtr;
   unsigned long   MemoryLength;
   char			   BufferedFileName[MAX_PATH];
  #ifdef __WIN32__RELEASE__
   HANDLE		   hTmpFilename;
   HANDLE          hMapping;
   DWORD lpBufferSize;
  #else
   int			  hTmpFilename;
  #endif
     
   char *UpdateFileMapping(); //Mapea los datos del fichero con bufferptr
public:
   HTTPIOMapping();
   HTTPIOMapping(unsigned int, char *);   
   ~HTTPIOMapping();   
   int			 InitializeFileMapping(unsigned int, char *); /* Initializa el filemapping */
   int			 WriteMappingData(unsigned int, char *lpData); //escribe los datos y llama a updatefileMapping() si es necesario.
   unsigned long GetMappingSize(void);
   char*		 GetMappingData(void);
   int			 IsAssigned(void);

};
/*******************************/
#endif

