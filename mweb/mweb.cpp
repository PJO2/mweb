// --------------------------------------------------------
// mweb.cpp
// by Ph. Jounin nov 2017
// 
// Sources : 
//		- MSDN "Complete Winsock Server Code" 
//		- nweb23.c from IBM and Nigel Griffiths
//		- tftpd32
// ---------------------------------------------------------

#define MWEB_VERSION "1.0"
#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <time.h>
#include <Strsafe.h>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

const char syntax[] = ""
"µweb: Usage\n"
"\n mweb [-4] [-6] [-p port] [-d dir] [-i addr] [-b bdwth] [-c content-type]"
"\n      [-s max connections] [-verbose]\n"
"\n      -4   IPv4 only"
"\n      -6   IPv6 only"
"\n      -b   limit bandwidth of each transfer (bandwidth specified in mbits/s)"
"\n      -c   content-type assigned to unknown files"
"\n           (default: reject unregistered types)"
"\n      -d   base directory for content (default is current directory)"
"\n      -i   listen only this address"
"\n      -p   HTTP port (defaut is 8080)"
"\n      -s   maximum simultaneous connection (default is 1024)"
"\n      -v   verbose"
"\n";


#define SYNTAX  syntax         

// default parameters
#define DEFAULT_BURST_PKTS    2
#define DEFAULT_BUFLEN       (1448*DEFAULT_BURST_PKTS)    // buffer size for reading HTTP command and file content (2 pkts of 1500 bytes)
#define DEFAULT_PORT         "8080"    
#define DEFAULT_MAXTHREADS   1024        // maximum simultaneous connections
#define DEFAULT_HTMLFILE    "index.html" // if request is "GET / HTTP/1.1"

#define TOCKENBUCKET_PERIOD  125		 // timer for tocken bucket in ms for shaping

// managed status code
enum { HTTP_OK=200, 
	   HTTP_PARTIAL=206, 
	   HTTP_BADREQUEST=400, 
	   HTTP_SECURITYVIOLATION=403, 
	   HTTP_NOTFOUND=404, 
	   HTTP_METHODNOTALLOWED=405, 
	   HTTP_TYPENOTSUPPORTED=415, 
	   HTTP_SERVERERROR=500 };

struct S_ErrorCodes
{
	int			status_code;
	const char *txt_content;
	const char *html_content;
}
sErrorCodes[] = 
{	
	{ HTTP_BADREQUEST,		  "Bad Request",            "HTTP malformed request syntax.",  },
	{ HTTP_NOTFOUND,		  "Not Found",              "The requested URL was not found on this server.",  },
	{ HTTP_SECURITYVIOLATION, "Forbidden",              "Directory traversal attack detected.",             },
	{ HTTP_TYPENOTSUPPORTED,  "Unsupported Media Type", "The requested file type is not allowed on this simple static file webserver.", },
	{ HTTP_METHODNOTALLOWED,  "Method Not Allowed",     "The requested file operation is not allowed on this simple static file webserver.", },
	{ HTTP_SERVERERROR,       "Internal Server Error",  "Internal Server Error, can not access to file anymore.", },
};

// params passed to logger funcion
enum { LOG_BEGIN, LOG_END, };		// 

// Global Settings 
struct S_Settings
{
	BOOL  bVerbose;
	BOOL  bIPv4;
	BOOL  bIPv6;
	char  *szPort;
	char  *szBoundTo;
	char  *szDefaultHtmlFile;
	DWORD  bandwidth;				// cmd line but converted in kBytes / seconds
	char  *szDefaultContentType;	// all files accepted with this content-type
	int    max_threads;				// maximum simultaneous connections
}
sSettings = { FALSE, FALSE, FALSE, DEFAULT_PORT, NULL,  DEFAULT_HTMLFILE, 0, NULL, DEFAULT_MAXTHREADS };


// The structure for each transfer
struct S_ThreadData
{
	SOCKET      skt;					// the transfer skt
	SOCKADDR_STORAGE sa;						// keep track of the client
	char       *buf;					// buffer for communication allocated in main thread
	unsigned    buflen;					// sizeof this buffer
	char        url_filename[MAX_PATH];	// URL to be retrieved
	char        long_filename[MAX_PATH];	// canonical file name with path
	char       *file_name;				// pointer inside long_filename
	char       *file_type;				// pointer inside long_filename
	HANDLE      hFile;					// file handle
	DWORD64     qwFileCurrentPos;		// pos in file (also the number of bytes sent to the client)
	DWORD64     qwFileSize;				// total size of the file
	time_t      tStartTrf;				// when the transfer has started

	// shaping data
	DWORD       bandwidth;				  // the transfer bandwidth copied from sSetting
	int         dwBurst;				  // bytes sent before pacing
	DWORD       dwBytesSentThisTimeUnit;  // counter for having last second stats
	SYSTEMTIME  sTockenBucketBase;		  // last pacing

	HANDLE      hThread;				  // thread handle
}
*sThreadData;			// array allocated in main

// known extensions for HTML content-type resolution
// from https://developer.mozilla.org/nl/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
// automatially generated from this url with the excel formula : 
// IF(C2="";CONCAT(" { """;A2;"""";", """;C1;""" }, ");CONCAT(" { """;A2;"""";", """;C2;""" }, "))
struct {
	char *ext;
	char *filetype;
} sHtmlTypes[] = {
	{ ".aac", "audio/aac" },
	{ ".abw", "application/x-abiword" },
	{ ".arc", "application/octet-stream" },
	{ ".avi", "video/x-msvideo" },
	{ ".azw", "application/vnd.amazon.ebook" },
	{ ".bin", "application/octet-stream" },
	{ ".bz", "application/x-bzip" },
	{ ".bz2", "application/x-bzip2" },
	{ ".csh", "application/x-csh" },
	{ ".css", "text/css" },
	{ ".csv", "text/csv" },
	{ ".doc", "application/msword" },
	{ ".eot", "application/vnd.ms-fontobject" },
	{ ".epub", "application/epub+zip" },
	{ ".gif", "image/gif" },
	{ ".htm", "text/html" },
	{ ".html", "text/html" },
	{ ".ico", "image/x-icon" },
	{ ".ics", "text/calendar" },
	{ ".jar",  "application/java-archive" },
	{ ".jpeg", "image/jpeg" },
	{ ".jpg",  "image/jpeg" },
	{ ".js",   "application/javascript" },
	{ ".json", "application/json" },
	{ ".mid", "audio/midi" },
	{ ".mid", "audio/midi" },
	{ ".mpeg", "video/mpeg" },
	{ ".mpkg", "application/vnd.apple.installer+xml" },
	{ ".odp", "application/vnd.oasis.opendocument.presentation" },
	{ ".ods", "application/vnd.oasis.opendocument.spreadsheet" },
	{ ".odt", "application/vnd.oasis.opendocument.text" },
	{ ".oga", "audio/ogg" },
	{ ".ogv", "video/ogg" },
	{ ".ogx", "application/ogg" },
	{ ".otf", "font/otf" },
	{ ".png", "image/png" },
	{ ".pdf", "application/pdf" },
	{ ".ppt", "application/vnd.ms-powerpoint" },
	{ ".rar", "application/x-rar-compressed" },
	{ ".rtf", "application/rtf" },
	{ ".sh", "application/x-sh" },
	{ ".svg", "image/svg+xml" },
	{ ".swf", "application/x-shockwave-flash" },
	{ ".tar", "application/x-tar" },
	{ ".tif", "image/tiff" },
	{ ".tiff", "image/tiff" },
	{ ".ts", "application/typescript" },
	{ ".ttf", "font/ttf" },
	{ ".vsd", "application/vnd.visio" },
	{ ".wav", "audio/x-wav" },
	{ ".weba", "audio/webm" },
	{ ".webm", "video/webm" },
	{ ".webp", "image/webp" },
	{ ".woff", "font/woff" },
	{ ".woff2", "font/woff2" },
	{ ".xhtml", "application/xhtml+xml" },
	{ ".xls", "application/vnd.ms-excel" },
	{ ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
	{ ".xml", "application/xml" },
	{ ".xul", "application/vnd.mozilla.xul+xml" },
	{ ".zip", "application/zip" },
	{ ".3gp", "video/3gpp" },
	{ ".3g2", "video/3gpp2" },
	{ ".7z", "application/x-7z-compressed" },

	// add-ons
	{ ".mp4",  "video/mpeg" }, 
	{ ".mpg",  "video/mpeg" }, 
	{ ".iso",  "application/iso" }, 
};


/////////////////////////////////////////////////////////////////
// utilities functions :
//      - report error
/////////////////////////////////////////////////////////////////


// Function LastErrorText : THREAD UNSAFE
// A wrapper for FormatMessage : retrieve the message text for a system-defined error
char *LastErrorText(void)
{
	static char szLastErrorText[512];
	LPVOID      lpMsgBuf;
	LPSTR       p;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,
					GetLastError(),
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
					(LPTSTR)&lpMsgBuf,
					0,
					NULL);
	StringCchCopyEx(szLastErrorText, sizeof szLastErrorText, (LPSTR)lpMsgBuf, NULL, NULL, STRSAFE_FILL_BEHIND_NULL);
	// Free the buffer.
	LocalFree(lpMsgBuf);
	// remove ending \r\n
	p = strchr(szLastErrorText, '\r');
	if (p != NULL)  *p = 0;
	return szLastErrorText;
} // LastErrorText



  // report an error to console using puts
void SVC_ERROR(const char *szFmt, ...)
{
	char szBuf[256];
	va_list args;
	if (sSettings.bVerbose)
	{
		va_start(args, szFmt);
		StringCchVPrintf(szBuf, sizeof szBuf, szFmt, args);
		puts(szBuf);
		va_end(args);
	}
} // SVC_ERROR


  /////////////////////////////////////////////////////////////////
  // utilities socket operations :
  //	  - check that socket is still opened by listen at it
  //	  - return MSS
  //      - bind its socket
  //      - init WSA socket
  //      - Check IPv6
  //      - send HTTP error
  /////////////////////////////////////////////////////////////////

int IsTransferCancelledByPeer(SOCKET skt)
{
	struct timeval to = { 0, 0 };
	fd_set fdset;
	char   recv_buf[4];
	int   iResult;
	// check if socket has been closed by client
	FD_ZERO(&fdset);
	FD_SET(skt, &fdset);
	iResult = select(0, &fdset, NULL, NULL, &to)>0
		&& recv(skt, recv_buf, sizeof recv_buf, 0) == 0;
	return iResult;
} // IsTransferCancelledByPeer


// return the max segment size for this socket
int GetSocketMSS(SOCKET skt)
{
int tcp_mss = 0;
int opt_len = sizeof tcp_mss;
int iResult;

	iResult = getsockopt(skt, IPPROTO_TCP, TCP_MAXSEG, (char*) & tcp_mss , & opt_len);
	if (iResult < 0)
	{
		SVC_ERROR("Failed to get TCP_MAXSEG for master socket.\nError %d (%s)", GetLastError(), LastErrorText());
		return -1;
	}
	return tcp_mss;
} // GetSocketMSS

int HTTPSendError (SOCKET skt, int HttpStatusCode)
{
char szBuf[512];
int  ark;
int  iResult;
const char szFormat[] = "HTTP/1.1 %d %s\nContent-Length: %d\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>%d %s</title>\n</head><body>\n<h1>%s</h1>\n%s\n</body></html>\n";
	// search error code in sErrorCodes array
	for ( ark=0 ; sErrorCodes[ark].status_code != 0  && sErrorCodes[ark].status_code!=HttpStatusCode ; ark++ );
	StringCchPrintf (szBuf, sizeof szBuf, szFormat, 
						sErrorCodes[ark].status_code, 
						sErrorCodes[ark].txt_content, 
					    lstrlen (sErrorCodes[ark].html_content) + 2 * lstrlen (sErrorCodes[ark].txt_content) + sizeof "<html><head>\n<title>400 </title>\n</head><body>\n<h1></h1>\n\n</body></html>\n" - 1,
						sErrorCodes[ark].status_code, 
						sErrorCodes[ark].txt_content, 
						sErrorCodes[ark].txt_content, 
						sErrorCodes[ark].html_content );
	iResult = send (skt, szBuf, lstrlen (szBuf), 0);
return iResult;
} // HTTPSendError 


// return TRUE IPv6 is enabled on the local system
BOOL IsIPv6Enabled(void)
{
	SOCKET s = INVALID_SOCKET;
	int Rc = 0;
	// just try to open an IPv6 socket
	s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	Rc = GetLastError();  // should be WSAEAFNOSUUPORT 10047
	closesocket(s);
	return s != INVALID_SOCKET;
} // IsIPv6Enabled


  // create a listening socket
  // and bind it to the HTTP port
SOCKET BindServiceSocket(int family, int type, const char *port, const char *sz_bind_addr)
{
	SOCKET             sListenSocket = INVALID_SOCKET;
	int                Rc;
	ADDRINFO           Hints, *res;

	memset(&Hints, 0, sizeof Hints);
	if (sSettings.bIPv4)  	Hints.ai_family = AF_INET;   // force IPv4
	else                        Hints.ai_family = family;    // use IPv4 or IPv6, whichever

															 // resolve the address and port we want to bind the server
	Hints.ai_socktype = type;
	Hints.ai_flags = AI_PASSIVE;     // fill in my IP for me
	Rc = getaddrinfo(sz_bind_addr,
		port,
		&Hints, &res);
	if (Rc != 0)
	{
		SVC_ERROR("Error : specified address %s is not recognized\nError %d (%s)", sz_bind_addr, GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}

	sListenSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sListenSocket == INVALID_SOCKET)
	{
		SVC_ERROR("Error : Can't create socket\nError %d (%s)", GetLastError(), LastErrorText());
		return INVALID_SOCKET;
	}


	// if family is AF_INET6, allow both IPv6 and IPv4 by disabling IPV6_ONLY (necessary since Vista)
	// http://msdn.microsoft.com/en-us/library/windows/desktop/bb513665(v=vs.85).aspx
	// does not work under XP --> do not check return code
	if (family == AF_INET6)
	{
		int Param = sSettings.bIPv6;		// set to false if bIpv6 is not set
		Rc = setsockopt(sListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)& Param, sizeof Param);
	}

	// bind the socket to the active interface
	Rc = bind(sListenSocket, res->ai_addr, res->ai_addrlen);
	if (Rc == INVALID_SOCKET)
	{
		SVC_ERROR("Error : Can't not bind socket\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}
	// create the listen queue
	Rc = listen(sListenSocket, 5);
	if (Rc == -1)
	{
		SVC_ERROR("Error : on listen\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(sListenSocket);
		return INVALID_SOCKET;
	}

	freeaddrinfo(res);
	return   Rc == INVALID_SOCKET ? Rc : sListenSocket;
} // BindServiceSocket


  // just call WSAStartup...
int InitSocket()
{
	WSADATA  wsa;
	int      iResult;
	iResult = WSAStartup(MAKEWORD(2, 0), &wsa);
	if (iResult < 0)
	{
		SVC_ERROR("Error : WSAStartup failed\nError %d (%s)", GetLastError(), LastErrorText());
		exit(-1);    // no recovery
	}
	return iResult;
} // InitSocket


  /////////////////////////////////////////////////////////////////
  // HTTP protocol management
  //      - decode incoming message
  //      - read file and send it through the Http channel
  // resources are freed by calling thread
  /////////////////////////////////////////////////////////////////

  // a minimal reporting
int LogTransfer(const struct S_ThreadData *pData, int when, int http_status)
{
	char szAddr[INET6_ADDRSTRLEN], szServ[NI_MAXSERV];
	char szBuf[256];

	if (!sSettings.bVerbose)  return 0;

	getnameinfo((LPSOCKADDR)& pData->sa, sizeof pData->sa,
				szAddr, sizeof szAddr,
				szServ, sizeof szServ,
				NI_NUMERICHOST | AI_NUMERICSERV);
	switch (when)
	{
		case LOG_BEGIN:
			StringCchPrintf(szBuf, sizeof szBuf, "From %s:%s, GET %s. burst size %d", szAddr, szServ, pData->file_name, pData->buflen);
			break;

		case LOG_END:
			StringCchPrintf(szBuf, sizeof szBuf, "From %s:%s, GET %s: %I64d bytes sent, status : %d",
				szAddr, szServ, pData->file_name,
				pData->qwFileCurrentPos, http_status );
			break;
	}
	return	puts(szBuf);
} // LogTransfer

  // utility : sub function for Shaper
inline void StartNewShapingPeriod(struct S_ThreadData *pData)
{
	GetSystemTime(&pData->sTockenBucketBase);		// start a new period
	pData->dwBurst = pData->dwBytesSentThisTimeUnit = 0;
}

// shape traffic to bandwidth (smoothed tocken bucket algorithm)
void Shaper(struct S_ThreadData *pData, DWORD bytes_read)
{
	int pacing;  // the number of ms to wait to keep the shaping
	SYSTEMTIME sNow;
	int real_time, expected_time;

	// keep 2 stats for two levels of shaping 
	// a burst before a pause of 10ms
	// a complete period of 125ms
	pData->dwBurst += bytes_read;
	pData->dwBytesSentThisTimeUnit += bytes_read;

	// the expected time to wait between two burst periods (if no rounding errors and no CPU sent)
	pacing = pData->dwBurst / pData->bandwidth; // bandwidth is not null

	if (pacing > 10)	// a pause is prepared
	{
		// time since the last period (use only milliseconds and seconds, 
		//   if minutes have changed, real_time will be uncorrectly <0, but we don not care)
		GetSystemTime(&sNow);
		real_time = sNow.wMilliseconds - pData->sTockenBucketBase.wMilliseconds
					+ (sNow.wSecond - pData->sTockenBucketBase.wSecond) * 1000;

		if (real_time < 0)	// either we do not deliver expected bandwidth or minutes have changed
		{
			StartNewShapingPeriod(pData);
		}
		else if (real_time > TOCKENBUCKET_PERIOD)		// correct pacing with timer
		{
			// expected time in ms to send the traffic at bandwidth kB/s
			expected_time = pData->dwBytesSentThisTimeUnit / pData->bandwidth;
			pacing = expected_time - real_time;		// corrrection with time already spent
			if (pacing>0) Sleep(pacing);
			StartNewShapingPeriod(pData);
		}
		else    // still in the same period
		{
			Sleep(--pacing);		// floor rouding of pacing
			pData->dwBurst = pData->dwBurst % pData->bandwidth;  // keep the modulo
		}
	}
} // Shaper

  // translate file extension into HTTP content-type field
  // Get extension type 
char *GetHtmlContentType(const char *os_extension)
{
int ark;

	if (os_extension == NULL)  
		return  sSettings.szDefaultContentType;

	// search for extension
	for (ark = 0; ark<sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]); ark++)
		if (lstrcmpi(sHtmlTypes[ark].ext, os_extension) == 0) break;
	if (ark >= sizeof(sHtmlTypes) / sizeof(sHtmlTypes[0]))
	{
		SVC_ERROR("Unregistered file extension");
		return sSettings.szDefaultContentType;		// NULL if not overridden
	}
	return sHtmlTypes[ark].filetype;
} // GetHtmlContentType


  // extract the file name 
  //			1- do not crash if we receive misformatted packets
  // HTTP formatting is GET _space_ file name ? arguments _space_ HTTP/VERSION _end of line_
BOOL ExtractFileName(const char *szHttpRequest, int request_length, char *szFileName, int name_size)
{
const char *pCur;
int         ark;
int         len;

	// check that request is long enough to find the file name
	if (request_length < sizeof "GET / HTTP/1.x\n" - 1) return FALSE;

	// set beginning of filename, then find its end (first space)
	// file name is supposed to start with '/', anyway accepts if / is missing
	pCur = szHttpRequest[4] == '/' ? &szHttpRequest[5] : &szHttpRequest[4];
	// search for next space, stop at the end of the string
	for (ark = 0;
		ark < request_length  &&  pCur[ark] != 0 && strchr("\r\n ?", pCur[ark]) == NULL;
		ark++);
	if (pCur[ark] != ' ' && pCur[ark] != '?')		// if anormal endings
	{
		return FALSE;
	}
	// now we ignore all the other stuff sent by client....
	// just copy the file name
	if (ark == 0)		// file name is /
		StringCchCopy(szFileName, name_size, sSettings.szDefaultHtmlFile);
	else
	{
		len = min(ark, name_size - 1);
		memcpy(szFileName, pCur, len);
		szFileName[len] = 0;
	}
	return TRUE;
} // ExtractFileName

// Read request and extract file name
// if error, can return abruptely: resources freed in calling funtions
int DecodeHttpRequest(struct S_ThreadData *pData, int request_length)
{
char     szCurDir[MAX_PATH];

	// double check buffer overflow
	if (request_length >= (int)pData->buflen)
		exit(-2);
	pData->buf[request_length] = 0;

	// ensure request is a GET
	CharUpperBuff(pData->buf, sizeof "GET " - 1);
	if (memcmp(pData->buf, "GET ", sizeof "GET " - 1) != 0)
	{
		SVC_ERROR("Only Simple GET operations supported");
		return HTTP_METHODNOTALLOWED;
	}
	// extract file name
	if (!ExtractFileName(pData->buf, request_length, pData->url_filename, sizeof pData->url_filename))
	{
		SVC_ERROR("invalid HTTP formatting");
		return HTTP_BADREQUEST;
	}
	// get canonical name && locate the file name location
	// Valid since we are in the main thread
	GetFullPathName(pData->url_filename, MAX_PATH, pData->long_filename, &pData->file_name);
	if (pData->file_name == NULL)
		pData->file_type = NULL;
	else
		pData->file_type = strrchr(pData->file_name, '.');	// search for '.'

	// sanity check : do not go backward in the directory structure
	GetFullPathName(".", MAX_PATH, szCurDir, NULL);
#ifdef UNSAFE__DEBUG
	printf("file to be retreived is %s, path is %s, file is %s, cur dir is %s\n", pData->long_filename, pData->buf, pData->file_name, szCurDir);
#endif
	if (memcmp(szCurDir, pData->long_filename, strlen(szCurDir)) != 0)
	{
		SVC_ERROR("directory traversal detected");
		return HTTP_SECURITYVIOLATION;
	}
return HTTP_OK;
} // DecodeHttpRequest

  // we don't expect anything from client, but it may abort the connection 



// Thread base
DWORD WINAPI HttpTransferThread(LPVOID lpParam)
{
int      bytes_rcvd;
DWORD    bytes_read;
char     *pContentType;
struct S_ThreadData *pData = (struct S_ThreadData *)  lpParam;
int      iResult = -1;
int      iHttpStatus=HTTP_BADREQUEST;
LARGE_INTEGER large;
int      tcp_mss;

	// get http request
	bytes_rcvd = recv(pData->skt, pData->buf, pData->buflen - 1, 0);
	if (bytes_rcvd < 0)
	{
		SVC_ERROR("Error in recv\nError %d (%s)", GetLastError(), LastErrorText());
		goto cleanup;
	}
	// modify buffer size depending on MSS
	if ( (tcp_mss = GetSocketMSS(pData->skt)) > 0 ) 
		pData->buflen = DEFAULT_BURST_PKTS * tcp_mss;

	// request is valid and pData filled with requested file
	iHttpStatus = DecodeHttpRequest(pData, bytes_rcvd);
	if (iHttpStatus != HTTP_OK)
		goto cleanup;

	// check extension and get the HTTP content=type of the file
	pContentType = GetHtmlContentType(pData->file_type);
	if (pContentType == NULL) 
	{
		iHttpStatus = HTTP_TYPENOTSUPPORTED;
		goto cleanup;
	}
	// open file
	pData->hFile = CreateFile(pData->long_filename, GENERIC_READ,
								FILE_SHARE_READ,
								NULL,
								OPEN_EXISTING,
								FILE_ATTRIBUTE_ARCHIVE | FILE_FLAG_SEQUENTIAL_SCAN,
								NULL);
	if (pData->hFile == INVALID_HANDLE_VALUE)
	{
		SVC_ERROR("Error opening file %s\nError %d (%s)", pData->long_filename, GetLastError(), LastErrorText());
		iHttpStatus = HTTP_NOTFOUND;
		goto cleanup;
	}

	GetFileSizeEx(pData->hFile, &large);
	pData->qwFileSize = large.QuadPart;

	// file accepted -> send HTTP 200 answer
	StringCchPrintf(pData->buf, pData->buflen,
					"HTTP/1.1 200 OK\nServer: mweb/%s\nContent-Length: %I64d\nConnection: close\nContent-Type: %s\n\n",
					MWEB_VERSION,
					pData->qwFileSize,
					pContentType); /* Header + a blank line */
	send(pData->skt, pData->buf, lstrlen(pData->buf), 0);
	LogTransfer(pData, LOG_BEGIN, 0);

	iHttpStatus = HTTP_PARTIAL;
	do
	{
		iResult = ReadFile(pData->hFile, pData->buf, pData->buflen, &bytes_read, NULL);
		send(pData->skt, pData->buf, bytes_read, 0);
		pData->qwFileCurrentPos += bytes_read;

		if (pData->bandwidth != 0)
			Shaper(pData, bytes_read);
		if (IsTransferCancelledByPeer(pData->skt)) 
			break;
	} while (iResult  &&  bytes_read>0);
	if (!iResult)		//note: if transfer cancelled report OK anyway
	{
		SVC_ERROR("Error in ReadFile\nError %d (%s)", GetLastError(), LastErrorText());
		iHttpStatus = HTTP_SERVERERROR;
		goto cleanup;
	}
	// if we reach this point file was successfully sent
	iHttpStatus = HTTP_OK;

cleanup:
	if (pData->skt != INVALID_SOCKET)
	{
		if (iHttpStatus >= HTTP_BADREQUEST)   
			HTTPSendError (pData->skt, iHttpStatus);
		closesocket(pData->skt);
		pData->skt = INVALID_SOCKET;
	}
	if (pData->buf != NULL)
	{
		LocalFree(pData->buf);
		pData->buf = NULL;
	}
	if (pData->hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(pData->hFile);
		pData->hFile = INVALID_HANDLE_VALUE;
	}
	// return Error to client
	LogTransfer(pData, LOG_END, iHttpStatus);
	Sleep(1000);
	return iResult ? 0 : -1;  // return a socket like return code

} // HttpTransferThread


  // Do Some cleanup on terminated Threads
int ManageTerminatedThread(struct S_ThreadData *sThreadData)
{
	int ark;
	DWORD  iResult;
	// check if threads have ended
	for (ark = 0; ark < sSettings.max_threads; ark++)
	{
		if (WaitForSingleObject(sThreadData[ark].hThread, 0) == WAIT_OBJECT_0)
		{
			GetExitCodeThread(sThreadData[ark].hThread, &iResult);
			CloseHandle(sThreadData[ark].hThread);
			// mark that slot is available by marking hThread
			sThreadData[ark].hThread = INVALID_HANDLE_VALUE;
		}
	}
	return ark;
} // ManageTerminatedThread


  /////////////////////////////////////////////////////////////////
  // main
  //      - create the listening socket
  //      - loop on waiting for incoming connection
  //        - start a new thread for each connection
  /////////////////////////////////////////////////////////////////

  // process args (mostly populate settings structure)
  // loosely processed : user can crash with invalid args...
int ParseCmdLine(int argc, char *argv[])
{
	int ark;
	for (ark = 1; ark < argc; ark++)
	{
		if (argv[ark][0] == '-')
		{
			switch (argv[ark][1])
			{
			case '4': sSettings.bIPv6 = FALSE; break;
			case '6': sSettings.bIPv4 = FALSE; break;
			case 'b': if (argv[ark + 1] != NULL)
				sSettings.bandwidth = atoi(argv[ark + 1]) * 1000 / 8;  // convert mbits/s to kBytes/s
				ark++;
				break;
			case 'c': sSettings.szDefaultContentType = argv[ark + 1];  ark++;  break;
			case 'd': if (!SetCurrentDirectory(argv[++ark]))
						SVC_ERROR("can not change directory to %s\nError %d (%s)",
									argv[ark], GetLastError(), LastErrorText());
				break;
			case 'i': sSettings.szBoundTo = argv[ark + 1];  ark++;  break;
			case 'p': sSettings.szPort = argv[++ark];  break;
			case 's': sSettings.max_threads = atoi(argv[ark + 1]); ark++; break;
			case 'v': sSettings.bVerbose = TRUE;   break;
			case 'x': sSettings.szDefaultHtmlFile = argv[ark + 1];  ark++;  break;
				break;
			default:
				puts(SYNTAX);
				exit(1);

			} // switch
		} // args prefixed by "-"
		else
		{
			puts(SYNTAX);
			exit(1);
		}
	} // for all args
	return ark;
} // ParseCmdLine


  // main loop 
void doLoop(SOCKET ListenSocket)
{
	SOCKADDR_STORAGE sa;
	int    sa_len;
	SOCKET ClientSocket;
	int    ark;
	DWORD  iResult;

	// Accept new client connection
	sa_len = sizeof sa;
	memset(&sa, 0, sizeof sa);
	ClientSocket = accept(ListenSocket, (struct sockaddr *) & sa, &sa_len);
	if (ClientSocket == INVALID_SOCKET) {
		SVC_ERROR("Error : Accept failed\nError %d (%s)", GetLastError(), LastErrorText());
		closesocket(ListenSocket);
		WSACleanup();
		exit(1);
	}

	// check if threads have ended
	for (ark = 0; ark < sSettings.max_threads; ark++)
	{
		if (WaitForSingleObject(sThreadData[ark].hThread, 0) == WAIT_OBJECT_0)
		{
			GetExitCodeThread(sThreadData[ark].hThread, &iResult);
			CloseHandle(sThreadData[ark].hThread);
			sThreadData[ark].hThread = INVALID_HANDLE_VALUE;
		}
	}

	// search first available slot
	for (ark = 0;
		ark < sSettings.max_threads && sThreadData[ark].hThread != INVALID_HANDLE_VALUE;
		ark++);

	if (ark >= sSettings.max_threads)
	{
		if (sSettings.bVerbose)
		    puts("ignore request : too many simultaneous transfers\n");
	}
	else
	{
		//populate sThreadData
		memset(&sThreadData[ark], 0, sizeof sThreadData[ark]);
		sThreadData[ark].sa = sa;
		sThreadData[ark].buflen = DEFAULT_BUFLEN;
		sThreadData[ark].buf = (char *)LocalAlloc(LPTR, sThreadData[ark].buflen + 1);
		sThreadData[ark].skt = ClientSocket;
		sThreadData[ark].qwFileCurrentPos = 0;
		sThreadData[ark].bandwidth = sSettings.bandwidth;
		time(&sThreadData[ark].tStartTrf);
		sThreadData[ark].dwBytesSentThisTimeUnit = 0;
		// Pass the socket id to a new thread and listen again
		sThreadData[ark].hThread = CreateThread(NULL,
												0,
												HttpTransferThread,
												&sThreadData[ark],
												0, NULL);
		// check allocated resources
		if (sThreadData[ark].buf == NULL || sThreadData[ark].hThread == INVALID_HANDLE_VALUE)
		{
			SVC_ERROR("can not allocate thread or memory");
		}
	} // slot available
} // doLoop



  // main program : read args, create listening socket and wait for incoming connections
int __cdecl main(int argc, char *argv[])
{
	SOCKET ListenSocket;
	int ark;
	char sbuf[MAX_PATH];

	ParseCmdLine(argc, argv); // override default settings
							  // Prepare the socket
	InitSocket();
	ListenSocket = BindServiceSocket(AF_INET6, SOCK_STREAM, sSettings.szPort, sSettings.szBoundTo);

	// init thread structure
	sThreadData = (struct S_ThreadData *) LocalAlloc(LPTR, sSettings.max_threads * sizeof sThreadData[0]);
	// all threads available
	for (ark = 0; ark < sSettings.max_threads; ark++)
		sThreadData[ark].hThread = INVALID_HANDLE_VALUE;

	GetCurrentDirectory(sizeof sbuf, sbuf);
	// if (sSettings.bVerbose)
		printf("mweb is listening on port %s, base directory is %s\n", 	sSettings.szPort, sbuf);

	for (; ; )
	{
		doLoop(ListenSocket);
	} // for (; ; )
	  // cleanup

	closesocket(ListenSocket);
	WSACleanup();

	return 0;
}

