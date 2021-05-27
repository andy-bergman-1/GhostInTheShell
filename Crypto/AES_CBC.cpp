
#include "pch.h"
#include <Common.h>

namespace Felidae {

    typedef struct {
        DWORD originSize;
        DWORD encrptyLen;
        BYTE data;
    }EncrptBuffer;

    BOOL AES_CBC_Encypt(
        LPBYTE lpData, DWORD dwSize,
        LPBYTE* lpEncryptData, DWORD* dwEncryptDataSize,
        LPBYTE aesKey, DWORD aesKeySize
    ) {
        AES_KEY aes;
        BYTE key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16  
        memset(key, 0, AES_BLOCK_SIZE);
        memcpy_s(key, AES_BLOCK_SIZE, aesKey, aesKeySize);

        BYTE iv[AES_BLOCK_SIZE];        // init vector  
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            iv[i] = (BYTE)i;
        }

        if (AES_set_encrypt_key(key, 128, &aes) < 0) {
            log("Unable to set encryption key in AES\n");
            return FALSE;
        }

        DWORD dwEncrptyLen = 0;
        if ((dwSize + 1) % AES_BLOCK_SIZE == 0) {
            dwEncrptyLen = dwSize + 1;
        }
        else {
            dwEncrptyLen = ((dwSize + 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        }

        *dwEncryptDataSize = dwEncrptyLen + 2 * sizeof(DWORD);
        *lpEncryptData = new BYTE[*dwEncryptDataSize];
        memset(*lpEncryptData, 0, *dwEncryptDataSize);
        EncrptBuffer* buf = (EncrptBuffer*)(*lpEncryptData);
        buf->encrptyLen = dwEncrptyLen;
        buf->originSize = dwSize;
        unsigned char* pData = &(buf->data);

        AES_cbc_encrypt(lpData, &(buf->data), dwEncrptyLen, &aes, iv, AES_ENCRYPT);
        return TRUE;
    }

    BOOL AES_CBC_Decrypt(
        LPBYTE lpEncryptData, DWORD dwEncryptDataSize,
        LPBYTE* lpData, DWORD* dwSize,
        LPBYTE aesKey, DWORD aesKeySize
    ) {
        AES_KEY aes;
        BYTE key[AES_BLOCK_SIZE];        // AES_BLOCK_SIZE = 16  
        memset(key, 0, AES_BLOCK_SIZE);
        memcpy_s(key, AES_BLOCK_SIZE, aesKey, aesKeySize);

        BYTE iv[AES_BLOCK_SIZE];        // init vector  
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
            iv[i] = (BYTE)i;
        }

        if (AES_set_decrypt_key(key, 128, &aes) < 0) {
            log("Unable to set encryption key in AES\n");
            *lpData = NULL;
            *dwSize = 0;
            return FALSE;
        }

        EncrptBuffer* buf = (EncrptBuffer*)lpEncryptData;
        if (buf->encrptyLen % AES_BLOCK_SIZE != 0
            || buf->encrptyLen + 2 * sizeof(DWORD) > dwEncryptDataSize
            || buf->originSize >= dwEncryptDataSize) {
            log("encrpty data  error\n");
            *lpData = NULL;
            *dwSize = 0;
            return FALSE;
        }

        *lpData = new BYTE[dwEncryptDataSize];
        memset(*lpData, 0, dwEncryptDataSize);
        AES_cbc_encrypt(&(buf->data), *lpData, buf->encrptyLen, &aes, iv, AES_DECRYPT);

        memset(*lpData + buf->originSize, 0, (dwEncryptDataSize - buf->originSize));

        *dwSize = buf->originSize;
        return TRUE;
    }


    BOOL AES_CBC_Encrypt_File(const char* input, const char* output, const char* aesKey) {
        LPBYTE lpData = NULL;
        DWORD dwSize = 0;
        if (!ReadFile(input, &lpData, &dwSize)) {
            log("failed to read file %s\n", input);
            return FALSE;
        }
        LPBYTE lpEncryptData = NULL;
        DWORD dwEncryptDataSize = 0;
        if (!AES_CBC_Encypt(lpData, dwSize, &lpEncryptData, &dwEncryptDataSize, (LPBYTE)aesKey, strlen(aesKey))) {
            delete[] lpData;
            return FALSE;
        }

        BOOL ok = WriteFile(output, lpEncryptData, dwEncryptDataSize);
        delete[] lpData;
        delete[] lpEncryptData;
        return ok;
    }


    BOOL AES_CBC_Decrypt_From_File(const char* input,
        LPBYTE* lpData, DWORD* dwSize,
        const char* aesKey
    ) {
        LPBYTE lpEncryptData = NULL;
        DWORD dwEncryptDataSize = 0;
        if (!ReadFile(input, &lpEncryptData, &dwEncryptDataSize)) {
            log("failed to read file %s\n", input);
            *lpData = NULL;
            *dwSize = 0;
            return FALSE;
        }
        if (!AES_CBC_Decrypt(lpEncryptData, dwEncryptDataSize, lpData, dwSize, (LPBYTE)aesKey, strlen(aesKey))) {
            delete[] lpEncryptData;
            *lpData = NULL;
            *dwSize = 0;
            return FALSE;
        }
        return TRUE;
    }

    BOOL AES_CBC_Decrypt_File(const char* input, const char* output, const char* aesKey) {
        LPBYTE lpEncryptData = NULL;
        DWORD dwEncryptDataSize = 0;
        if (!ReadFile(input, &lpEncryptData, &dwEncryptDataSize)) {
            log("failed to read file %s\n", input);
            return FALSE;
        }
        LPBYTE lpData = NULL;
        DWORD dwSize = 0;
        if (!AES_CBC_Decrypt(lpEncryptData, dwEncryptDataSize, &lpData, &dwSize, (LPBYTE)aesKey, strlen(aesKey))) {
            delete[] lpEncryptData;
            return FALSE;
        }

        BOOL ok = WriteFile(output, lpData, dwSize);
        delete[] lpData;
        delete[] lpEncryptData;
        return ok;
    }

    BOOL AES_CBC_Encrypt_String(const char* input, char** output, const char* aesKey) {
        LPBYTE lpData = (LPBYTE)input;
        DWORD dwSize = strlen(input);
        LPBYTE lpEncryptData = NULL;
        DWORD dwEncryptDataSize = 0;
        if (!AES_CBC_Encypt(lpData, dwSize, &lpEncryptData, &dwEncryptDataSize, (LPBYTE)aesKey, strlen(aesKey))) {
            return FALSE;
        }
        BytesToHex(lpEncryptData, dwEncryptDataSize, output);
        delete[] lpEncryptData;
        return TRUE;
    }

    BOOL AES_CBC_Decrypt_String(const char* input, char** output, const char* aesKey) {
        LPBYTE lpEncryptData = NULL;
        DWORD dwEncryptDataSize = 0;
        if (!HexToBytes(input, &lpEncryptData, &dwEncryptDataSize)) {
            log("%s input string is not hex format\n", input);
            return FALSE;
        }
        DWORD dwOutputSize = 0;
        BOOL ok = AES_CBC_Decrypt(lpEncryptData, dwEncryptDataSize, (LPBYTE*)output, &dwOutputSize, (LPBYTE)aesKey, strlen(aesKey));
        
        delete[] lpEncryptData;
        return ok;
    }
}