#include "pch.h"


namespace Felidae {

    char hexToByte(char f) {
        if (f >= '0' && f <= '9') {
            return f - '0';
        }
        else if (f >= 'a' && f <= 'f') {
            return f - 'a' + 10;
        }
        return -1;
    }


	void BytesToHex(LPBYTE lpData, DWORD dwSize, char** lpHex) {
        DWORD dwHexByteSize = dwSize * 2 + 1;
        LPBYTE hex = new BYTE[dwHexByteSize];
        memset(hex, 0, dwHexByteSize);

        for (unsigned int i = 0; i < dwSize; i++) {
            BYTE b = lpData[i];
            sprintf_s(
                (char *)&(hex[i * 2]),
                ((size_t)dwSize - i) * 2 + 1,
                "%x%x",
                (b >> 4) & 0xf, 
                b & 0xf
            );
        }
        *lpHex = (char *)hex;
	}
	BOOL HexToBytes(char const* lpHex, LPBYTE* lpData, DWORD* dwSize) {

        size_t sizeHex = strlen(lpHex);
        if (sizeHex % 2 != 0) {
            *lpData = NULL;
            *dwSize = 0;
            return FALSE;
        }

        DWORD _dwSize = sizeHex / 2;
        LPBYTE _lpData = new BYTE[(size_t)_dwSize + 1];
        memset(_lpData, 0, (size_t)_dwSize + 1);
        for (size_t i = 0; i < _dwSize; i++) {
            char b0 = lpHex[i * 2];
            char b1 = lpHex[i * 2 + 1];
            b0 = hexToByte(b0);
            b1 = hexToByte(b1);
            if (b0 == -1 || b1 == -1) {
                delete[] _lpData;
                *lpData = NULL;
                *dwSize = 0;
                return FALSE;
            }
            _lpData[i] = (b0 << 4) + (b1 & 0xf);
        }
        *lpData = _lpData;
        *dwSize = _dwSize;
		return TRUE;
	}
}