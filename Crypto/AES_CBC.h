#pragma once

#include <Windows.h>

namespace Felidae {

    BOOL AES_CBC_Encypt(
        LPBYTE lpData, DWORD dwSize,
        LPBYTE* lpEncryptData, DWORD* dwEncryptDataSize,
        LPBYTE aesKey, DWORD aesKeySize
    );

    BOOL AES_CBC_Decrypt(
        LPBYTE lpEncryptData, DWORD dwEncryptDataSize,
        LPBYTE* lpData, DWORD* dwSize,
        LPBYTE aesKey, DWORD aesKeySize
    );


    BOOL AES_CBC_Encrypt_File(const char* input, const char* output, const char* aesKey);
    BOOL AES_CBC_Decrypt_File(const char* input, const char* output, const char* aesKey);
    BOOL AES_CBC_Decrypt_From_File(const char* input, LPBYTE* lpData, DWORD* dwSize, const char* aesKey);
    BOOL AES_CBC_Encrypt_String(const char* input, char** output, const char* aesKey);
    BOOL AES_CBC_Decrypt_String(const char* input, char** output, const char* aesKey);

}
