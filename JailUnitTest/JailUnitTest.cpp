// JailUnitTest.cpp : Defines the entry point for the console application.
//
// This application takes in a TLV structure that will describe an action to perform.
// The valid actions are:
//  * Read an arbitrary file
//  * Write an arbitrary file
//  * Query directory listing at an arbitrary location
//  * Create a one-shot server socket at an arbitrary port
//  * Create a client socket to an arbitrary host and port
//  * List all processes

#include "stdafx.h"

#define NASSERT(cond) { \
	if (!(cond)) { \
		goto Exit; \
	} \
}

namespace Pickle {
	template <typename T>
	bool Read(T *value)
	{
		bool status = false;
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		DWORD readBytes = 0;

		NASSERT(value);
		NASSERT(ReadFile(hStdin, value, sizeof(*value), &readBytes, NULL));
		NASSERT(readBytes == sizeof(*value));

		status = true;

	Exit:
		return status;
	}
	
	bool ReadBlob(PBYTE *buffer, DWORD *size)
	{
		bool status = false;
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		DWORD readBytes = 0;
		UINT16 rawSize = 0;
		PBYTE pBuffer = NULL;

		NASSERT(buffer && size);
		NASSERT(Read<UINT16>(&rawSize));
		pBuffer = (PBYTE)malloc(rawSize);
		NASSERT(pBuffer);
		NASSERT(ReadFile(hStdin, pBuffer, rawSize, &readBytes, NULL));
		NASSERT(readBytes == rawSize);

		*buffer = pBuffer;
		*size = rawSize;
		pBuffer = NULL;

		status = true;

	Exit:
		if (pBuffer) {
			free(pBuffer);
		}

		return status;
	}

	bool ReadString(LPTSTR *value)
	{
		bool status = false;
		PBYTE buffer = NULL;
		DWORD size = 0;

		NASSERT(ReadBlob(&buffer, &size));
		*value = (LPTSTR)buffer;

		status = true;

	Exit:
		return status;
	}

	template <typename T>
	bool Write(T *value)
	{
		bool status = false;
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD writtenBytes = 0;

		NASSERT(value);
		NASSERT(WriteFile(hStdout, value, sizeof(*value), &writtenBytes, NULL));
		NASSERT(writtenBytes == sizeof(*value));

		status = true;

	Exit:
		return status;
	}

	bool WriteBlob(PBYTE buffer, DWORD size)
	{
		bool status = false;
		HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		DWORD writtenBytes = 0;
		UINT16 rawSize = (UINT16)size;

		NASSERT(buffer && size > 0);
		NASSERT(Write<UINT16>(&rawSize));

		NASSERT(WriteFile(hStdout, buffer, size, &writtenBytes, NULL));
		NASSERT(writtenBytes == size);

		status = true;

	Exit:
		return status;
	}

	bool WriteString(LPTSTR value)
	{
		bool status = false;
		DWORD size = (_tcslen(value) + 1) * sizeof(_TCHAR);

		NASSERT(size < MAXUINT16);
		NASSERT(WriteBlob((PBYTE)value, size));

		status = true;

	Exit:
		return status;
	}
}

#define JUT_READ_FILE        1
#define JUT_WRITE_FILE       2
#define JUT_QUERY_DIRECTORY  3
#define JUT_BIND_ECHOSERVER  4
#define JUT_SEND_ECHOCLIENT  5
#define JUT_LIST_PROCESSES   6
#define JUT_EXEC_SHELLCODE   7

void WriteHeader(bool status, UINT32 code)
{
	UINT32 statusHdr = status ? 1 : 0;
	Pickle::Write<UINT32>(&statusHdr);
	Pickle::Write<UINT32>(&code);
}

bool Do_ReadFile()
{
	bool status = false;
	LPTSTR path = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PBYTE buffer = NULL;
	LARGE_INTEGER li = { 0 };
	DWORD size = 0;
	DWORD readBytes = 0;

	NASSERT(Pickle::ReadString(&path));
	hFile = CreateFile(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	NASSERT(hFile != INVALID_HANDLE_VALUE);
	NASSERT(GetFileSizeEx(hFile, &li));
	
	size = li.LowPart < 2048 ? li.LowPart : 2048;
	buffer = (PBYTE)malloc(size);
	NASSERT(buffer);
	NASSERT(ReadFile(
		hFile,
		buffer,
		size,
		&readBytes,
		NULL));

	WriteHeader(true, 0);
	Pickle::WriteBlob(buffer, readBytes);

	status = true;
Exit:
	if (!status) {
		WriteHeader(status, GetLastError());
	}
	if (path) {
		free(path);
	}
	if (buffer != NULL) {
		free(buffer);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	return status;
}

bool Do_WriteFile()
{
	bool status = false;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	LPTSTR path = NULL;
	PBYTE buffer = NULL;
	DWORD size = 0;
	DWORD writtenBytes = 0;

	NASSERT(Pickle::ReadString(&path));
	NASSERT(Pickle::ReadBlob(&buffer, &size));

	hFile = CreateFile(
		path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	NASSERT(hFile != INVALID_HANDLE_VALUE);
	NASSERT(WriteFile(
		hFile,
		buffer,
		size,
		&writtenBytes,
		NULL));
	
	WriteHeader(true, 0);
	status = true;
Exit:
	if (!status) {
		WriteHeader(status, GetLastError());
	}
	if (path) {
		free(path);
	}
	if (buffer) {
		free(buffer);
	}
	if (hFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
	}
	return status;
}

bool Do_QueryDirectory()
{
	bool status = false;
	LPTSTR path = NULL;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA fd = { 0 };
	DWORD sentinel = -1;

	NASSERT(Pickle::ReadString(&path));

	hFind = FindFirstFile(
		path,
		&fd);
	NASSERT(hFind != INVALID_HANDLE_VALUE);

	WriteHeader(true, 0);

	do {
		Pickle::Write<DWORD>(&fd.dwFileAttributes);
		Pickle::Write<DWORD>(&fd.nFileSizeHigh);
		Pickle::Write<DWORD>(&fd.nFileSizeLow);
		Pickle::WriteString((LPTSTR) &fd.cFileName);
		RtlZeroMemory(&fd, sizeof(fd));
	} while (FindNextFile(hFind, &fd));

	Pickle::Write<DWORD>(&sentinel);
	status = true;
Exit:
	if (!status) {
		WriteHeader(status, GetLastError());
	}
	if (path) {
		free(path);
	}
	if (hFind != INVALID_HANDLE_VALUE) {
		FindClose(hFind);
	}
	return status;
}

bool Do_BindEchoServer()
{
	bool status = false;
	SOCKET srvfd = INVALID_SOCKET;
	SOCKET newfd = INVALID_SOCKET;
	UINT16 port = 0;
	struct sockaddr_in srvaddr = { 0 };

	NASSERT(Pickle::Read<UINT16>(&port));

	srvfd = socket(AF_INET, SOCK_STREAM, 0);
	NASSERT(srvfd != INVALID_SOCKET);

	srvaddr.sin_family = AF_INET;
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	srvaddr.sin_port = htons(port);
	
	NASSERT(bind(srvfd, (struct sockaddr *) &srvaddr, sizeof(srvaddr)) != -1);
	NASSERT(listen(srvfd, 10) != -1);

	WriteHeader(true, 0);

	status = true;
Exit:
	if (!status) {
		WriteHeader(status, WSAGetLastError());
	}
	if (srvfd != INVALID_SOCKET) {
		closesocket(srvfd);
	}
	return status;
}

bool Do_SendEchoClient()
{
	bool status = false;
	LPSTR host = NULL;
	LPSTR port = NULL;
	DWORD size = 0;
	SOCKET s = INVALID_SOCKET;
	struct addrinfo hints = { 0 };
	struct addrinfo *servinfo = NULL;
	struct addrinfo *p = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	NASSERT(Pickle::ReadString((LPTSTR *)&host));
	NASSERT(Pickle::ReadString((LPTSTR *)&port));

	NASSERT(getaddrinfo(host, port, &hints, &servinfo) == 0);
	for (p = servinfo; p != NULL; p = p->ai_next) {
		s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (s == INVALID_SOCKET) {
			continue;
		}

		if (connect(s, p->ai_addr, p->ai_addrlen) == -1) {
			closesocket(s);
			continue;
		}

		break;
	}

	WriteHeader(true, 0);
	status = true;
Exit:
	if (!status) {
		WriteHeader(status, WSAGetLastError());
	}
	if (host) {
		free(host);
	}
	if (port) {
		free(port);
	}
	if (s != INVALID_SOCKET) {
		closesocket(s);
	}
	return status;
}

bool Do_ListProcesses()
{
	bool status = false;
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 ppe = { 0 };
	DWORD sentinel = -1;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	NASSERT(hSnap != INVALID_HANDLE_VALUE);

	ppe.dwSize = sizeof(ppe);
	NASSERT(Process32First(hSnap, &ppe));

	WriteHeader(true, 0);

	do {
		Pickle::Write<DWORD>(&ppe.th32ProcessID);
		Pickle::WriteString((LPTSTR) &ppe.szExeFile);
	} while (Process32Next(hSnap, &ppe));

	Pickle::Write<DWORD>(&sentinel);
	status = true;
Exit:
	if (!status) {
		WriteHeader(status, GetLastError());
	}
	if (hSnap != INVALID_HANDLE_VALUE) {
		CloseHandle(hSnap);
	}
	return status;
}

bool Do_ExecShellcode()
{
	bool status = false;
	PBYTE buffer = NULL;
	PBYTE execBuf = NULL;
	DWORD size = 0;
	
	NASSERT(Pickle::ReadBlob(&buffer, &size));
	execBuf = (PBYTE)VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	NASSERT(execBuf);

	RtlCopyMemory(execBuf, buffer, size);
	((void (*)()) execBuf)();

	WriteHeader(true, 0);
	status = true;
Exit:
	if (!status) {
		WriteHeader(status, GetLastError());
	}
	if (execBuf) {
		VirtualFree(execBuf, size, MEM_DECOMMIT);
	}
	if (buffer) {
		free(buffer);
	}
	return status;
}

int _tmain(int argc, _TCHAR* argv[])
{
	int nret = -1;
	WSADATA wsaData = { 0 };
	DWORD sizeOfChar = sizeof(_TCHAR);
	BYTE opcode = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	NASSERT(WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

	// First, send a DWORD containing the size of a _TCHAR
	NASSERT(Pickle::Write<DWORD>(&sizeOfChar));

	while (1) {
		NASSERT(Pickle::Read<BYTE>(&opcode));

		// FIXME: remove the NASSERTs
		switch (opcode) {
		case JUT_READ_FILE:
			Do_ReadFile();
			break;
		case JUT_WRITE_FILE:
			Do_WriteFile();
			break;
		case JUT_QUERY_DIRECTORY:
			Do_QueryDirectory();
			break;
		case JUT_BIND_ECHOSERVER:
			Do_BindEchoServer();
			break;
		case JUT_SEND_ECHOCLIENT:
			Do_SendEchoClient();
			break;
		case JUT_LIST_PROCESSES:
			Do_ListProcesses();
			break;
		case JUT_EXEC_SHELLCODE:
			Do_ExecShellcode();
			break;
		default:
			goto Exit;
		}
	}

	nret = 0;

Exit:
	WSACleanup();
	return nret;
}

