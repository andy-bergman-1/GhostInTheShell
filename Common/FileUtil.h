#pragma once

#include <Windows.h>

namespace Felidae {

	BOOL WriteFile(
		const char *path,
		LPBYTE lpData,
		DWORD dwSize
	);
	BOOL ReadFile(
		const char* path,
		LPBYTE* lpData,
		DWORD* dwSize
	);
}
