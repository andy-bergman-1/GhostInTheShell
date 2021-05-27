
#include "pch.h"

namespace Felidae {

	BOOL WriteFile(
		const char* path,
		LPBYTE lpData,
		DWORD dwSize
	) {
		HANDLE hFile = ::CreateFile(
			path,
			GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);
		if (hFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		BOOL ok = ::WriteFile(
			hFile,
			lpData,
			dwSize,
			NULL,
			NULL
		);
		::CloseHandle(hFile);
		return ok;
	}

	BOOL ReadFile(
		const char* path,
		LPBYTE* lpData,
		DWORD* dwSize
	) {
		HANDLE hFile = ::CreateFile(
			path, 
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_ARCHIVE,
			NULL
		);
		if (hFile == INVALID_HANDLE_VALUE) {
			*lpData = NULL;
			*dwSize = 0;
			return FALSE;
		}

		::SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
		DWORD dwFileSize = ::GetFileSize(hFile, NULL);

		LPBYTE lpBuf = new BYTE[dwFileSize];
		memset(lpBuf, 0, dwFileSize);

		BOOL ok = ::ReadFile(
			hFile,
			lpBuf,
			dwFileSize,
			NULL,
			NULL
		);
		if (!ok) {
			*lpData = NULL;
			*dwSize = 0;
			delete[] lpBuf;
		}
		else {
			*lpData = lpBuf;
			*dwSize = dwFileSize;
		}
		::CloseHandle(hFile);
		return ok;
	}
}