// AppJailLauncher.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include "common.h"
#include "utils.h"

typedef struct _CMD_OPTIONS
{
	BOOL HelpEnabled;
	BOOL UninstallEnabled;
	BOOL OutboundNetworkEnabled;
	BOOL NoJail;
	USHORT Port;
	DWORD TimeoutSeconds;
	LPTSTR KeyFilePath;
	LPTSTR ChildFilePath;
} CMD_OPTIONS, *PCMD_OPTIONS;

#define ArgMatchesOption(arg, option)                       (_tcsicmp(arg, _T(option)) == 0)
#define ArgMatchesOptionWithArgument(arg, option, minsize)  (_tcsnicmp(arg, _T(option), _tcslen(_T(option))) == 0 && \
                                                             _tcslen(arg) > (_tcslen(_T(option)) + minsize - 1)) 
#define GetOptionArgument(arg, option)                      ((_TCHAR *) (arg + _tcslen(_T(option))))

#define DEFAULT_PORT     4444
#define DEFAULT_TIMEOUT  5

#define ShowError(fmt, ...) { \
	PRINT(fmt, __VA_ARGS__); \
	PRINT(" For help, use the /help switch.\n"); \
}
#define CheckFileOrDirectoryAttributes(cond) { \
	DWORD dwAttributes = GetFileAttributes(pszFilePath); \
	if (dwAttributes == INVALID_FILE_ATTRIBUTES) { \
		return FALSE; \
	} \
	return (cond); \
}

BOOL g_keepListening = TRUE;
WSAEVENT g_hQuitListenEvent = WSA_INVALID_EVENT;

BOOL FileExists(LPTSTR pszFilePath)
{
	CheckFileOrDirectoryAttributes((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

BOOL DirectoryExists(LPTSTR pszFilePath)
{
	CheckFileOrDirectoryAttributes((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
}

VOID ShowHelp(LPTSTR pszProgramPath)
{
	PRINT("Usage: %s [/help] [/uninstall] {options} child-process-path\n", pszProgramPath);
	PRINT("  Actions:\n");
	PRINT("    /help               Displays this message.\n");
	PRINT("    /uninstall          By running the application jail launcher program,  \n");
	PRINT("                        an AppContainer profile will be created on the local\n");
	PRINT("                        machine. Additionally, if a /key switch is provided,\n");
	PRINT("                        the key-file-path parent directory and file will both\n");
	PRINT("                        have an ACL entry added for the AppContainer SID. The\n");
	PRINT("                        /uninstall switch deletes the AppContainer profile and\n");
	PRINT("                        and removes ACL entries from the key-file-path parent\n");
	PRINT("                        directory and file\n");
	PRINT("\n");
	PRINT("    By default, the standard action is to install the AppContainer profile and\n");
	PRINT("    associated access control entries if necessary and start listening as a server.\n");
	PRINT("\n");
	PRINT("  Options:\n");
	PRINT("    /outbound           This switch enables the executable to be executed\n");
	PRINT("                        upon a client socket connection the ability to use\n");
	PRINT("                        networking capability.\n");
	PRINT("    /nojail             This option disables the creation of an AppContainer process.\n");
	PRINT("                        A normal process will be created instead with the same permissions\n");
	PRINT("                        as the parent process. (NOT RECOMMENDED)\n");
	PRINT("    /port:number        Specifies the port number for the server to listen to.\n");
	PRINT("                        The default port is %i.\n", DEFAULT_PORT);
	PRINT("    /timeout:seconds    Specifies the number of seconds to allow the child\n");
	PRINT("                        process to run before terminating. This is mostly to\n");
	PRINT("                        prevent abuse and \"griefing\". The default is %i seconds.\n", DEFAULT_TIMEOUT);
	PRINT("    /key:key-file-path  This switch specifies a file that should be used as\n");
	PRINT("                        the \"key\" file in a capture-the-flag challenge. By\n");
	PRINT("                        specifying a file, the file and the file's parent\n");
	PRINT("                        directory will both have new access control entries\n");
	PRINT("                        added to their access control lists allowing the current\n");
	PRINT("                        AppContainer read access.\n");
	PRINT("\n");
	PRINT("  child-process-path    A file path to an executable that is to be executed\n");
	PRINT("                        upon a client socket connection. The STDIN, STDOUT,\n");
	PRINT("                        and STDERR of this executable is redirected to the \n");
	PRINT("                        client socket. The AppContainer profile name is derived\n");
	PRINT("                        from the child-process-path's filename. This helps avoid\n");
	PRINT("                        using a single AppContainer profile which may need to\n");
	PRINT("                        cross-contamination between capture-the-flag challenges.\n");
	PRINT("\n");
	PRINT("  Examples:\n");
	PRINT("    %s /outbound /key:flag /port:4141 /timeout:2 C:\\work\\child.exe\n", pszProgramPath);
	PRINT("    %s /uninstall /key:flag C:\\work\\child.exe\n", pszProgramPath);
}

HRESULT ParseCommandLineArgs(int argc, _TCHAR *argv[], PCMD_OPTIONS pCmdOpts)
{
	HRESULT hr = E_FAIL;

	RtlZeroMemory(pCmdOpts, sizeof(*pCmdOpts));

	for (int i = 1; i < argc; i++) {
		if (ArgMatchesOption(argv[i], "/help")) {
			pCmdOpts->HelpEnabled = TRUE;
		}
		else if (ArgMatchesOption(argv[i], "/uninstall")) {
			pCmdOpts->UninstallEnabled = TRUE;
		}
		else if (ArgMatchesOption(argv[i], "/outbound")) {
			pCmdOpts->OutboundNetworkEnabled = TRUE;
		}
		else if (ArgMatchesOption(argv[i], "/nojail")) {
			pCmdOpts->NoJail = TRUE;
		}
		else if (ArgMatchesOptionWithArgument(argv[i], "/port:", 2)) {
			USHORT usPort = (USHORT) _tcstoul(GetOptionArgument(argv[i], "/port:"), NULL, 10);
			if (usPort == 0) {
				goto Exit;
			}

			pCmdOpts->Port = usPort;
		}
		else if (ArgMatchesOptionWithArgument(argv[i], "/timeout:", 1)) {
			DWORD dwTimeout = _tcstoul(GetOptionArgument(argv[i], "/timeout:"), NULL, 10);
			if (dwTimeout == 0) {
				goto Exit;
			}

			pCmdOpts->TimeoutSeconds = dwTimeout;
		}
		else if (ArgMatchesOptionWithArgument(argv[i], "/key:", 1)) {
			pCmdOpts->KeyFilePath = GetOptionArgument(argv[i], "/key:");
		}
		else {
			if (pCmdOpts->ChildFilePath) {
				goto Exit;
			}

			pCmdOpts->ChildFilePath = argv[i];
		}
	}

	hr = S_OK;
Exit:
	return hr;
}

BOOL WINAPI HandleCtrlCPress(DWORD dwCtrlType)
{
	if (dwCtrlType == CTRL_C_EVENT) {
		if (g_keepListening) {
			LOG("Control-C detected. Setting event.\n");
			if (g_hQuitListenEvent != WSA_INVALID_EVENT) {
				WSASetEvent(g_hQuitListenEvent);
			}

			g_keepListening = FALSE;
		}
		return TRUE;
	}
	else {
		return FALSE;
	}
}

HRESULT GetFullKeyPathAndKeyParentDirectory(
	LPCTSTR pszKeyFilePath,
	LPTSTR pszFullKeyPath,
	DWORD cbFullKeyPath,
	LPTSTR pszCurrentDirectory,
	DWORD cbCurrentDirectory
	) {
	HRESULT hr = E_FAIL;
	LPTSTR pszKeyFileSpec = NULL;

	W32_ASSERT(GetFullPathName(
		pszKeyFilePath,
		cbFullKeyPath,
		pszFullKeyPath,
		&pszKeyFileSpec
		) > 0, Exit);
	_tcscpy_s(
		pszCurrentDirectory,
		cbCurrentDirectory - 1,
		pszFullKeyPath
		);
	W32_ASSERT(PathRemoveFileSpec(pszCurrentDirectory), Exit);

	hr = S_OK;
Exit:
	return hr;
}

int Do_Uninstall(LPTSTR pszChildFilePath, LPTSTR pszKeyFilePath)
{
	int nret = -1;

	PSID pApplicationSid = NULL;

	_TCHAR szFullKeyPath[1024] = { 0 };
	_TCHAR szCurrentDirectory[1024] = { 0 };

	LOG("Do_Uninstall entered.\n");
	LOG("  ChildFilePath: %s\n", pszChildFilePath);
	LOG("  KeyFilePath:   %s\n", pszKeyFilePath);

	if (!SUCCEEDED(GetAppContainerSid(pszChildFilePath, &pApplicationSid))) {
		PRINT("AppContainer profile for %s does not exist.\n", pszChildFilePath);
		goto Exit;
	}

	LOG("AppContainer SID at 0x%016p\n", pApplicationSid);

	if (pszKeyFilePath) {
		ASSERT(SUCCEEDED(GetFullKeyPathAndKeyParentDirectory(
			pszKeyFilePath,
			szFullKeyPath,
			(sizeof(szFullKeyPath) / sizeof(_TCHAR)),
			szCurrentDirectory,
			(sizeof(szCurrentDirectory) / sizeof(_TCHAR))
			)), Exit);

		LOG("  FullKeyPath: %s\n", szFullKeyPath);
		LOG("  FullKeyDir: %s\n", szCurrentDirectory);

		// Remove the AppContainer's SID from the ACL of the key
		ASSERT(SUCCEEDED(AddOrRemoveAceOnFileObjectAcl(
			TRUE,
			szFullKeyPath,
			pApplicationSid,
			GENERIC_READ
			)), Exit);

		// Remove the AppContainer's SID fro the ACL of the key's parent directory
		ASSERT(SUCCEEDED(AddOrRemoveAceOnFileObjectAcl(
			TRUE,
			szCurrentDirectory,
			pApplicationSid,
			GENERIC_READ | GENERIC_EXECUTE
			)), Exit);
	}

	if (SUCCEEDED(DestroyAppContainerProfile(pszChildFilePath))) {
		PRINT("AppContainer profile for %s deleted.\n", pszChildFilePath);
	}
	else {
		PRINT("Failed to delete AppContainer profile for %s.\n", pszChildFilePath);
	}

	nret = 0;

Exit:
	if (pApplicationSid != NULL) {
		FreeSid(pApplicationSid);
	}

	return nret;
}

int Do_LaunchServer(
	LPTSTR pszChildFilePath, 
	LPTSTR pszKeyFilePath, 
	USHORT usPort, 
	DWORD dwTimeout, 
	BOOL bNetworkEnabled,
	BOOL bNoJail)
{
	int nret = -1;
	HRESULT hr = E_FAIL;
	WSADATA wsaData = { 0 };
	SOCKET serverSocket = INVALID_SOCKET;
	PSID pApplicationSid = NULL;
	HANDLE hJob = INVALID_HANDLE_VALUE;
	
	LPCTSTR pszCapabilitiesList[2] = { 0 };

	socklen_t sin_size = 0;
	struct sockaddr_storage clientAddr = { 0 };

	_TCHAR clientIpAddr[64] = { 0 };
	_TCHAR szFullKeyPath[1024] = { 0 };
	_TCHAR szCurrentDirectory[1024] = { 0 };
	LPTSTR pszCurrentDirectory = NULL;

	DWORD dwReturnCode = 0;
	WSAEVENT hAcceptEvent = WSA_INVALID_EVENT;
	WSAEVENT EventList[2] = { 0 };

	LOG("Do_LaunchServer entered.\n");

	WS2_ASSERT(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0, Exit);

	LOG("  ChildFilePath:  %s\n", pszChildFilePath);
	LOG("  KeyFilePath:    %s\n", pszKeyFilePath);
	LOG("  ServerPort:     %i\n", usPort);
	LOG("  ChildTimeout:   %i seconds\n", dwTimeout);
	LOG("  NetworkEnabled: %s\n", bNetworkEnabled ? _T("True") : _T("False"));

	// Find or create AppContainer sid
	if (!SUCCEEDED(FindOrCreateAppContainerProfile(pszChildFilePath, &pApplicationSid))) {
		PRINT("Failed to find or create an AppContainer profile for %s\n", pszChildFilePath);

		goto Exit;
	}

	if (pszKeyFilePath) {
		ASSERT(SUCCEEDED(GetFullKeyPathAndKeyParentDirectory(
			pszKeyFilePath,
			szFullKeyPath,
			(sizeof(szFullKeyPath) / sizeof(_TCHAR)),
			szCurrentDirectory,
			(sizeof(szCurrentDirectory) / sizeof(_TCHAR))
			)), Exit);
		pszCurrentDirectory = szCurrentDirectory;

		LOG("  KeyFilePath: %s\n", szFullKeyPath);
		LOG("  KeyCurrentDirectory: %s\n", szCurrentDirectory);

		// Add an ACE containing the AppContainer's SID into key's parent directory's ACL
		hr = AddOrRemoveAceOnFileObjectAcl(
			FALSE,
			szCurrentDirectory,
			pApplicationSid,
			GENERIC_READ | GENERIC_EXECUTE
			);
		if (!SUCCEEDED(hr)) {
			ASSERT(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), Exit);
			LOG("  Adding ACE into key parent directory's ACL failed because ACE already exists.\n");
		}

		// Add an ACE containing the AppContainer's SID into key's ACL
		hr = AddOrRemoveAceOnFileObjectAcl(
			FALSE,
			szFullKeyPath,
			pApplicationSid,
			GENERIC_READ
			);
		if (!SUCCEEDED(hr)) {
			ASSERT(hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS), Exit);
			LOG("  Adding ACE into key's ACL failed because ACE already exists.\n");
		}
	}

	if (bNetworkEnabled) {
		LOG("Network access is enabled in child process.\n");

		pszCapabilitiesList[0] = NETWORK_ACCESS_CAPABILITY;
	}

	LOG("Creating job object for limiting processing time.\n");
	if (!SUCCEEDED(CreateLimitProcessTimeJobObject(dwTimeout, &hJob))) {
		PRINT("Failed to create limit process time job object.\n");

		goto Exit;
	}

	LOG("Creating and listening on new socket on  port %i.\n", usPort);
	if (!SUCCEEDED(SocketCreateAndListen(usPort, &serverSocket))) {
		PRINT("Failed to create and listen on a socket.\n");

		goto Exit;
	}

	LOG("Setting listening socket to not inheritable.\n");
	W32_ASSERT(SetHandleInformation(
		(HANDLE)serverSocket,
		HANDLE_FLAG_INHERIT,
		0), Exit);

	LOG("Creating WSA events.\n");
	hAcceptEvent = WSACreateEvent();
	WS2_ASSERT(hAcceptEvent != WSA_INVALID_EVENT, Exit);

	g_hQuitListenEvent = WSACreateEvent();
	WS2_ASSERT(g_hQuitListenEvent != WSA_INVALID_EVENT, Exit);

	EventList[0] = hAcceptEvent;
	EventList[1] = g_hQuitListenEvent;

	LOG("Setting WSAEventSelect.\n");
	WS2_ASSERT(WSAEventSelect(
		serverSocket,
		hAcceptEvent,
		FD_ACCEPT
		) != SOCKET_ERROR, Exit);
	
	LOG("Installing Ctrl-C handler.\n");
	W32_ASSERT(SetConsoleCtrlHandler(HandleCtrlCPress, TRUE), Exit);

	PRINT("Listening for incoming connections on port %i...\n", usPort);
	while (g_keepListening) {
		SOCKET clientSocket = INVALID_SOCKET;
		sin_size = sizeof(clientAddr);

		dwReturnCode = WSAWaitForMultipleEvents(
			sizeof(EventList) / sizeof(WSAEVENT),
			EventList,
			FALSE,
			INFINITE,
			FALSE
			);
		if (dwReturnCode == WSA_WAIT_EVENT_0) {
			LOG("Sensed new client connection.\n");

			clientSocket = accept(
				serverSocket,
				(struct sockaddr *) &clientAddr,
				&sin_size
				);
			if (clientSocket != INVALID_SOCKET) {
				RtlZeroMemory(clientIpAddr, sizeof(clientIpAddr));
				PRINT(
					"  Client connection from %s accepted.\n",
					InetNtop(
					((struct sockaddr_in *) &clientAddr)->sin_family,
					(PVOID)&((struct sockaddr_in *) &clientAddr)->sin_addr,
					clientIpAddr,
					sizeof(clientIpAddr)
					)
					);

				if (SUCCEEDED(CreateClientSocketWorker(
					clientSocket,
					hJob,
					pszCurrentDirectory,
					pApplicationSid,
					pszChildFilePath,
					bNoJail ? FALSE : TRUE,
					pszCapabilitiesList
					))) {
					LOG("  Jailed process launched successfully.\n");
				}
				else {
					LOG("  Failed to launch jailed process.\n");
				}

				closesocket(clientSocket);
				WS2_ASSERT(WSAResetEvent(hAcceptEvent), Exit);
			}
			else {
				ERR(
					"Bad client request (nret = %08x, WSAGetLastError() = %i), client dropped.\n", 
					clientSocket,
					WSAGetLastError()
					);
			}
		}
		else if (dwReturnCode == WSA_WAIT_EVENT_0 + 1) {
			LOG("g_hQuitListenEvent is set. Exiting.\n");
			PRINT("Ctrl-C event detected. Exiting...\n");
			break;
		}
		else {
			// XXX: This should be unreached...
			//   Other possible cases as per MSDN documentation:
			//    * WSA_WAIT_IO_COMPLETION - This value is only returned when fAlertable is TRUE.
			//                               fAlertable is FALSE in my call.
			//    * WSA_WAIT_TIMEOUT - This happens when the time-out interval has elapsed. However,
			//                         our interval is INFINITE.
			LOG("Unexpected value: dwReturnCode=%08x\n", dwReturnCode);
		}
	}

	LOG("Removing Ctrl-C handler.\n");
	W32_ASSERT(SetConsoleCtrlHandler(HandleCtrlCPress, FALSE), Exit);
	PRINT("Goodbye.\n");

	nret = 0;

Exit:
	if (hAcceptEvent != WSA_INVALID_EVENT) {
		WSACloseEvent(hAcceptEvent);
	}

	if (g_hQuitListenEvent != WSA_INVALID_EVENT) {
		WSACloseEvent(g_hQuitListenEvent);
	}

	if (hJob != INVALID_HANDLE_VALUE) {
		CloseHandle(hJob);
	}

	if (pApplicationSid != NULL) {
		FreeSid(pApplicationSid);
	}

	if (serverSocket != INVALID_SOCKET) {
		closesocket(serverSocket);
	}

	WSACleanup();

	return nret;
}

int _tmain(int argc, _TCHAR* argv[])
{
	CMD_OPTIONS CmdOpts = { 0 };

	if (!SUCCEEDED(ParseCommandLineArgs(argc, argv, &CmdOpts))) {
		ShowError("Invalid commandline argument specified.");

		return 1;
	}
	
	// If help switch is set, show the help menu and quit
	if (CmdOpts.HelpEnabled) {
		ShowHelp(argv[0]);

		return 0;
	}

	// Child file path must be a valid pointer and be an existent file
	if (CmdOpts.ChildFilePath == NULL) {
		ShowError("No child process file path specified.");

		return -1;
	}

	// TODO: should we remove this check to be just a command-line argument?
	// if (!FileExists(CmdOpts.ChildFilePath)) {
	//   ShowError("%s does not exist.", CmdOpts.ChildFilePath);
	// 
	// 	 return -1;
	// }

	// If a key file path is specified, make sure the file actually exists
	if (CmdOpts.KeyFilePath && !FileExists(CmdOpts.KeyFilePath)) {
		ShowError("Key file %s does not exist.", CmdOpts.KeyFilePath);

		return -1;
	}

	// If no port is specified, use the default port
	if (CmdOpts.Port == 0) {
		CmdOpts.Port = DEFAULT_PORT;
	}

	// If no timeout is specified, use the default timeout in seconds
	if (CmdOpts.TimeoutSeconds == 0) {
		CmdOpts.TimeoutSeconds = DEFAULT_TIMEOUT;
	}

	// Parse the action to take
	if (CmdOpts.UninstallEnabled) {
		return Do_Uninstall(CmdOpts.ChildFilePath, CmdOpts.KeyFilePath);
	}
	else {
		return Do_LaunchServer(
			CmdOpts.ChildFilePath, 
			CmdOpts.KeyFilePath, 
			CmdOpts.Port, 
			CmdOpts.TimeoutSeconds, 
			CmdOpts.OutboundNetworkEnabled,
			CmdOpts.NoJail
			);
	}
}

