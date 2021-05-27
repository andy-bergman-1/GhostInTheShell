#include <stdio.h>
#include <Crypto.h>
#include <Common.h>

typedef struct {
    BOOL decrypt;
    char* inputString;
    char* inputFile;
    char* outputFile;
    char* aesKey;
} Options;

void printHelp(int argc, char** argv) {
    fprintf(stderr, "\n%s -k <aes key> <-e|-d> [-f <input file>] [-s <input string>] [-o <output string>]\n", argv[0]);
    fprintf(stderr, "  -k key\n");
    fprintf(stderr, "  -e encrypt\n");
    fprintf(stderr, "  -d decrypt\n");
    fprintf(stderr, "  -f input file\n");
    fprintf(stderr, "  -o output file\n");
    fprintf(stderr, "  -s input string\n");
}

BOOL parseOpts(int argc, char** argv, Options* opts) {
    memset(opts, 0, sizeof(Options));

    int i = 1;
    while (i < argc) {
        char* a = argv[i];
        if (strcmp(a, "-f") == 0) {
            i++;
            if (i >= argc) {
                return FALSE;
            }
            opts->inputFile = argv[i];
        }
        else if (strcmp(a, "-o") == 0) {
            i++;
            if (i >= argc) {
                return FALSE;
            }
            opts->outputFile = argv[i];
        }
        else if (strcmp(a, "-s") == 0) {
            i++;
            if (i >= argc) {
                return FALSE;
            }
            opts->inputString = argv[i];
        }
        else if (strcmp(a, "-k") == 0) {
            i++;
            if (i >= argc) {
                return FALSE;
            }
            opts->aesKey = argv[i];
        }
        else if (strcmp(a, "-d") == 0) {
            opts->decrypt = TRUE;
        }
        else if (strcmp(a, "-e") == 0) {
            opts->decrypt = FALSE;
        }
        else {
            fprintf(stderr, "unknown argument %s\n", a);
            return FALSE;
        }
        i++;
    }
    if (opts->inputFile == NULL && opts->inputString == NULL) {
        fprintf(stderr, "-f or -s required\n");
        return FALSE;
    }

    if (opts->inputFile != NULL) {
        if (opts->inputString != NULL) {
            fprintf(stderr, "-f argument has setted, do not set -s argument\n");
            return FALSE;
        }
        if (opts->outputFile == NULL) {
            fprintf(stderr, "-o argument required\n");
            return FALSE;
        }
    }
    if (opts->inputString != NULL) {
        if (opts->outputFile != NULL) {
            fprintf(stderr, "do not need -o argument\n");
            return FALSE;
        }
    }

    return TRUE;

}


int main(int argc, char** argv) {
    Options opts;
    if (!parseOpts(argc, argv, &opts)) {
        printHelp(argc, argv);
        return -1;
    }


    if (opts.inputFile) {
        if (opts.decrypt) {
            Felidae::AES_CBC_Decrypt_File(opts.inputFile, opts.outputFile, opts.aesKey);
        }
        else {
            Felidae::AES_CBC_Encrypt_File(opts.inputFile, opts.outputFile, opts.aesKey);
        }
    }
    else if (opts.inputString) {
        if (opts.decrypt) {
            char* ptr = NULL;
            fprintf(stderr, "input: %s\n", opts.inputString);
            if (Felidae::AES_CBC_Decrypt_String(opts.inputString, &ptr, opts.aesKey)) {
                fprintf(stderr, "decrypted: %s\n", ptr);
                printf("%s", ptr);
                delete[] ptr;
            }
        }
        else {
            char* ptr = NULL;
            fprintf(stderr, "input: %s\n", opts.inputString);
            if (Felidae::AES_CBC_Encrypt_String(opts.inputString, &ptr, opts.aesKey)) {
                fprintf(stderr, "encrypted: %s\n", ptr);
                printf("%s", ptr);
                delete[] ptr;
            }
        }
    }
    return 0;
}
