#pragma once

#include <Windows.h>

namespace Felidae {

	void BytesToHex(LPBYTE lpData, DWORD dwSize, char** lpHex);
	BOOL HexToBytes(char const* lpHex, LPBYTE* lpData, DWORD* dwSize);

}
