// utils.cpp : Defines the utility functions

#include "utils.h"

HRESULT SocketCreateAndListen(USHORT usPort, SOCKET *pSocket)
{
	HRESULT hr = E_FAIL;
	CHAR szPort[8] = { 0 };
	_TCHAR szAddr[64] = { 0 };

	SOCKET s = INVALID_SOCKET;
	struct addrinfo hints = { 0 };
	struct addrinfo *servinfo = NULL;
	struct addrinfo *p = NULL;

	int yes = 1;

	ASSERT(sprintf_s(szPort, sizeof(szPort), "%i", usPort) > 0, Exit);

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	ASSERT(pSocket != NULL, Exit);

	*pSocket = INVALID_SOCKET;

	WS2_ASSERT(getaddrinfo(NULL, szPort, &hints, &servinfo) == 0, Exit);
	for (p = servinfo; p != NULL; p = p->ai_next) {
		s = WSASocket(p->ai_family, p->ai_socktype, p->ai_protocol, NULL, NULL, NULL);
		if (s == INVALID_SOCKET) continue;

		WS2_ASSERT(setsockopt(
			s,
			SOL_SOCKET,
			SO_REUSEADDR,
			(const char *) &yes,
			sizeof(yes)
			) == 0, Exit);

		if (bind(s, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket(s);
			continue;
		}

		break;
	}

	LOG(
		"Socket bound on %s:%i\n",
		InetNtop(
			p->ai_family,
			(PVOID) &((struct sockaddr_in *) p->ai_addr)->sin_addr,
			szAddr,
			sizeof(szAddr) / sizeof(_TCHAR)
			),
		htons(((struct sockaddr_in *) p->ai_addr)->sin_port)
		);

	ASSERT(listen(s, 5) == 0, Exit);
	LOG("Listening for new connections...\n");

	*pSocket = s;
	s = INVALID_SOCKET;

	hr = S_OK;
Exit:
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}

	if (servinfo != NULL) {
		freeaddrinfo(servinfo);
	}

	return hr;
}

HRESULT FindOrCreateAppContainerProfile(LPCTSTR pszChildFilePath, PSID *ppSid)
{
	HRESULT hr = E_FAIL;
	HRESULT _hr = E_FAIL;

	PTSTR pszAppContainerName = PathFindFileName(pszChildFilePath);
	PSID pSid = NULL;

	ASSERT(ppSid != NULL, Exit);
	*ppSid = NULL;

	LOG("Trying to create a new AppContainer profile \"%s\".\n", pszAppContainerName);
	_hr = CreateAppContainerProfile(
		pszAppContainerName,
		pszAppContainerName,
		_T("Child worker process"),
		NULL,
		0,
		&pSid
		);
	if (_hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
		LOG(
			"Profile \"%s\" already exists. Retrieving SID from existing profile.\n",
			pszAppContainerName
			);
		W32_ASSERT(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
			pszAppContainerName,
			&pSid
			)), Exit);
		_hr = S_OK;
	}
	ASSERT(SUCCEEDED(_hr), Exit);

	LOG("AppContainer profile SID obtained.\n");
	*ppSid = pSid;
	pSid = NULL;

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT GetAppContainerSid(LPCTSTR pszChildFilePath, PSID *ppSid)
{
	HRESULT hr = E_FAIL;
	
	PTSTR pszAppContainerName = PathFindFileName(pszChildFilePath);
	PSID pSid = NULL;

	LOG("Retrieving AppContainer SID for %s (%s).\n", pszChildFilePath, pszAppContainerName);
	W32_ASSERT(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
		pszAppContainerName,
		&pSid
		)), Exit);

	*ppSid = pSid;
	pSid = NULL;

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT DestroyAppContainerProfile(LPCTSTR pszChildFilePath)
{
	HRESULT hr = E_FAIL;
	PTSTR pszAppContainerName = PathFindFileName(pszChildFilePath);
	PSID pSid = NULL;

	ASSERT(pszChildFilePath != NULL, Exit);

	LOG("Trying to get AppContainer profile for \"%s\".\n", pszAppContainerName);
	W32_ASSERT(SUCCEEDED(DeriveAppContainerSidFromAppContainerName(
		pszAppContainerName,
		&pSid
		)), Exit);

	LOG("Deleting AppContainer profile \"%s\".\n", pszAppContainerName);
	W32_ASSERT(SUCCEEDED(DeleteAppContainerProfile(pszAppContainerName)), Exit);

	hr = S_OK;
Exit:
	if (pSid != NULL) {
		FreeSid(pSid);
	}

	return hr;
}

HRESULT AddOrRemoveAceOnFileObjectAcl(
	BOOL IsRemoveOperation,
	LPCTSTR pszFilePath,
	PSID pSid,
	DWORD dwAccessMask
	)
{
	HRESULT hr = E_FAIL;

	DWORD DescSize = 0;
	SECURITY_DESCRIPTOR NewDesc = { 0 };
	PSECURITY_DESCRIPTOR pOldDesc = NULL;

	BOOL DaclPresent = FALSE;
	BOOL DaclDefaulted = FALSE;
	DWORD cbNewDacl = 0;
	PACL pOldDacl = NULL;
	PACL pNewDacl = NULL;
	ACL_SIZE_INFORMATION AclInfo = { 0 };

	ULONG i = 0;
	LPVOID pTempAce = NULL;

	ASSERT(pszFilePath != NULL, Exit);
	ASSERT(pSid != NULL, Exit);
	LOG("Entering Utils_AddOrRemoveAceOnFileAcl...IsRemoveOperation=%i\n", IsRemoveOperation);

	LOG("Retrieving SECURITY_DESCRIPTOR for %s...\n", pszFilePath);
	W32_ASSERT(GetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		NULL,
		0,
		&DescSize
		) == 0, Exit);
	LOG("SECURITY_DESCRIPTOR size is %d\n", DescSize);

	LOG("Allocating memory for new security descriptor\n");
	pOldDesc = (PSECURITY_DESCRIPTOR) ALLOC(DescSize);
	ASSERT(pOldDesc != NULL, Exit);

	W32_ASSERT(GetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		pOldDesc,
		DescSize,
		&DescSize
		) != 0, Exit);
	LOG("SECURITY_DESCRIPTOR is at %016p\n", pOldDesc);

	W32_ASSERT(InitializeSecurityDescriptor(
		&NewDesc,
		SECURITY_DESCRIPTOR_REVISION
		), Exit);
	LOG("New SECURITY_DESCRIPTOR is initialized\n");

	LOG("Obtaining DACL from SECURITY_DESCRIPTOR...\n");
	W32_ASSERT(GetSecurityDescriptorDacl(
		pOldDesc,
		&DaclPresent,
		&pOldDacl,
		&DaclDefaulted
		), Exit);
	LOG("DACL at %016p and is%s present.\n", pOldDacl, DaclPresent ? _T("") : _T(" not"));
	ASSERT(pOldDacl != NULL, Exit); // TODO: FIXME: This is a possible scenario
	                                //   On certain file systems, a DACL will not be present.
	                                //   For now, we will just exit with an error. Perhaps in
	                                //   the future, creating a new DACL might work out better.

	AclInfo.AceCount = 0;
	AclInfo.AclBytesFree = 0;
	AclInfo.AclBytesInUse = sizeof(ACL);

	W32_ASSERT(GetAclInformation(
		pOldDacl,
		&AclInfo,
		sizeof(AclInfo),
		AclSizeInformation
		), Exit);

	if (IsRemoveOperation) {
		cbNewDacl = AclInfo.AclBytesInUse - sizeof(ACCESS_ALLOWED_ACE) - GetLengthSid(pSid) + sizeof(DWORD);
	}
	else {
		cbNewDacl = AclInfo.AclBytesInUse + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pSid) - sizeof(DWORD);
	}

	LOG("Allocating %d bytes for new DACL\n", cbNewDacl);
	pNewDacl = (PACL) ALLOC(cbNewDacl);
	ASSERT(pNewDacl != NULL, Exit);
	W32_ASSERT(InitializeAcl(
		pNewDacl,
		cbNewDacl,
		ACL_REVISION
		), Exit);

	if (IsRemoveOperation) {
		for (i = 0; i < AclInfo.AceCount; i++) {
			W32_ASSERT(GetAce(pOldDacl, i, &pTempAce), Exit);
			if (!EqualSid(pSid, &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart))) {
				W32_ASSERT(AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize), Exit);
			}
		}
	}
	else {
		for (i = 0; i < AclInfo.AceCount; i++) {
			W32_ASSERT(GetAce(pOldDacl, i, &pTempAce), Exit);
			if (((ACCESS_ALLOWED_ACE *)pTempAce)->Header.AceFlags & INHERITED_ACE) break;
			if (EqualSid(pSid, &(((ACCESS_ALLOWED_ACE *)pTempAce)->SidStart))) {
				hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
				goto Exit;
			}
			W32_ASSERT(AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize), Exit);
		}

		W32_ASSERT(AddAccessAllowedAce(
			pNewDacl,
			ACL_REVISION,
			dwAccessMask,
			pSid
			), Exit);
		LOG("Adding new AccessAllowedAce\n");

		for (; i < AclInfo.AceCount; i++) {
			W32_ASSERT(GetAce(pOldDacl, i, &pTempAce), Exit);
			W32_ASSERT(AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize), Exit);
		}
	}

	LOG("Setting new DACL to new SECURITY_DESCRIPTOR...\n");
	W32_ASSERT(SetSecurityDescriptorDacl(
		&NewDesc,
		TRUE,
		pNewDacl,
		FALSE
		), Exit);

	LOG("Setting new SECURITY_DESCRIPTOR to %s\n", pszFilePath);
	W32_ASSERT(SetFileSecurity(
		pszFilePath,
		DACL_SECURITY_INFORMATION,
		&NewDesc
		), Exit);

	LOG("ACL %s succeeded\n", IsRemoveOperation ? _T("remove") : _T("add"));
	hr = S_OK;
Exit:
	if (pNewDacl != NULL) {
		FREE(pNewDacl);
	}

	if (pOldDesc != NULL) {
		FREE(pOldDesc);
	}

	return hr;
}

HRESULT CreateLimitProcessTimeJobObject(DWORD dwTimeout, PHANDLE phJob)
{
	HRESULT hr = E_FAIL;

	HANDLE hJob = INVALID_HANDLE_VALUE;
	LARGE_INTEGER tl = { 0 };
	JOBOBJECT_BASIC_LIMIT_INFORMATION bli = { 0 };

	LOG("Trying to create a new job object with timeout of %i seconds.\n", dwTimeout);
	hJob = CreateJobObject(NULL, NULL);
	W32_ASSERT(hJob != INVALID_HANDLE_VALUE, Exit);
	LOG("New job object created with handle %016p\n", hJob);

	tl.LowPart = dwTimeout;
	bli.PerProcessUserTimeLimit = tl;
	bli.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_TIME;

	LOG("Setting job object information.\n");
	W32_ASSERT(SetInformationJobObject(
		hJob,
		JobObjectBasicLimitInformation,
		&bli,
		sizeof(bli)
		), Exit);

	LOG("Job information set.\n");
	*phJob = hJob;
	hJob = INVALID_HANDLE_VALUE;

	hr = S_OK;
Exit:
	if (hJob != INVALID_HANDLE_VALUE) {
		CloseHandle(hJob);
	}

	return hr;
}

HRESULT CreateClientSocketWorker(
	SOCKET s,
	HANDLE hJob,
	LPCTSTR pszCurrentDirectory,
	PSID pAppContainerSid,
	LPCTSTR pszChildFilePath,
	BOOL bWorkerIsJailed,
	LPCTSTR *pszCapabilities
	)
{
	HRESULT hr = E_FAIL;

	LPTSTR pszCommandLine = NULL;
	PSID pSid = NULL;
	DWORD dwCreationFlags = CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
	DWORD dwCapabilitiesCount = 0;
	DWORD dwAttributeListSize = 0;
	LPPROC_THREAD_ATTRIBUTE_LIST AttributeList = NULL;
	PSID_AND_ATTRIBUTES CapabilitiesList = NULL;
	SECURITY_CAPABILITIES SecurityCapabilities = { 0 };

	STARTUPINFOEX si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	ASSERT(s != INVALID_SOCKET, Exit);
	ASSERT(hJob != INVALID_HANDLE_VALUE, Exit);
	ASSERT(pAppContainerSid != NULL, Exit);
	ASSERT(pszChildFilePath != NULL, Exit);

	// Parse a list of capability SIDs in string format only if the list is not NULL NS
	// the worker is to be jailed.
	if (bWorkerIsJailed && pszCapabilities) {
		LOG("pszCapabilities is not NULL, counting items.\n");
		while (pszCapabilities[dwCapabilitiesCount] != NULL) {
			dwCapabilitiesCount++;
		}

		LOG("Found %i capabilities.\n", dwCapabilitiesCount);
		if (dwCapabilitiesCount > 0) {
			LOG("Creating capabilities attribute list for %i capabilities.\n", dwCapabilitiesCount);
			CapabilitiesList = (PSID_AND_ATTRIBUTES)ALLOC(dwCapabilitiesCount * sizeof(SID_AND_ATTRIBUTES));
			ASSERT(CapabilitiesList != NULL, Exit);

			for (DWORD i = 0; i < dwCapabilitiesCount; i++) {
				pSid = NULL;
				W32_ASSERT(ConvertStringSidToSid(pszCapabilities[i], &pSid), Exit);
				CapabilitiesList[i].Sid = pSid;
				CapabilitiesList[i].Attributes = SE_GROUP_ENABLED;
			}
		}
	}
	else {
		LOG("No capabilities provided.\n");
	}

	// Handle cases in which the client worker process is not to be jailed. 
	// TODO:
	//   In the future, this may need to be refactored for when we have another AttributeList
	//   item (for inherited HANDLEs).
	if (bWorkerIsJailed) {
		// Set up security capabilities
		SecurityCapabilities.AppContainerSid = pAppContainerSid;
		SecurityCapabilities.Capabilities = CapabilitiesList;
		SecurityCapabilities.CapabilityCount = dwCapabilitiesCount;

		// Set up thread attribute list
		W32_ASSERT(!InitializeProcThreadAttributeList(
			NULL,
			1,
			0,
			&dwAttributeListSize
			), Exit);

		LOG("Allocating memory for AttributeList (%i bytes)\n", dwAttributeListSize);
		AttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)ALLOC(dwAttributeListSize);
		ASSERT(AttributeList != NULL, Exit);

		LOG("Initializing AttributeList at 0x%016p\n", AttributeList);
		W32_ASSERT(InitializeProcThreadAttributeList(
			AttributeList,
			1,
			0,
			&dwAttributeListSize
			), Exit);

		LOG("Updating AttributeList with security capabilities.\n");
		W32_ASSERT(UpdateProcThreadAttribute(
			AttributeList,
			0,
			PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
			&SecurityCapabilities,
			sizeof(SecurityCapabilities),
			NULL,
			NULL), Exit);

		// For spawning jailed process, we need to set the count to sizeof(STARTUPINFOEX) for
		// the attribute list
		si.StartupInfo.cb = sizeof(si);
		si.lpAttributeList = AttributeList;

		// Make sure CreateProcess knows it is using extended STARTUPINFO
		dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
	}
	else {
		// We are not jailing the client worker so we pretend to send a normal STARTUPINFO structure
		si.StartupInfo.cb = sizeof(si.StartupInfo);
	}
	LOG("si.StartupInfo.cb = %i\n", si.StartupInfo.cb);

	// Setup STDIN/STDOUT/STDERR redirection
	LOG("Redirecting STDIN/STDOUT/STDERR of the new application.\n");
	si.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.StartupInfo.hStdInput = (HANDLE) s;
	si.StartupInfo.hStdOutput = (HANDLE) s;
	si.StartupInfo.hStdError = (HANDLE) s;
	si.StartupInfo.wShowWindow = SW_HIDE;
	
	// Copy the child file path and spawn process
	LOG("Copying pszChildFilePath to pszCommandLine.\n");
	pszCommandLine = (LPTSTR) ALLOC((_tcslen(pszChildFilePath) + 2) * sizeof(_TCHAR));
	ASSERT(pszCommandLine != NULL, Exit);
	_tcscpy_s(pszCommandLine, _tcslen(pszChildFilePath) + 1, pszChildFilePath);

	LOG("Launching new process \"%s\".\n", pszCommandLine);
	W32_ASSERT(CreateProcess(
		NULL,
		pszCommandLine,
		NULL,
		NULL,
		TRUE, // TODO: FIXME: I don't like how we're just blanket allowing all handles to be
		      //              inherited.
		dwCreationFlags,
		NULL,
		pszCurrentDirectory,
		(LPSTARTUPINFO) &si,
		&pi
		), Exit);
	
	LOG("Assigning job (handle=%016p) to new process PID=%i.\n", hJob, pi.dwProcessId);
	if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
		ERR("Failed to assign process to job object. GetLastError() = %i\n", GetLastError());
		ERR("Terminating process PID=%i\n", pi.dwProcessId);

		TerminateProcess(pi.hProcess, -1);
		hr = HRESULT_FROM_WIN32(GetLastError());
		goto Exit;
	}

	LOG("Resuming new process' thread TID=%i\n", pi.dwThreadId);
	W32_ASSERT(ResumeThread(pi.hThread), Exit);

	hr = S_OK;

Exit:
	if (pszCommandLine) {
		FREE(pszCommandLine);
	}

	if (AttributeList != NULL) {
		FREE(AttributeList);
	}

	if (CapabilitiesList != NULL) {
		for (ULONG i = 0; i < dwCapabilitiesCount; i++) {
			LocalFree(CapabilitiesList[i].Sid);
		}
		FREE(CapabilitiesList);
	}
    
    if (pi.hThread != NULL && pi.hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(pi.hThread);
    }

    if (pi.hProcess != NULL && pi.hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(pi.hProcess);
    }

	return hr;
}
