#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <algorithm>
#include <lmcons.h>

PPEB pPeb = (PPEB) __readgsqword(0x60);

BOOL IsHexString(WCHAR *szStr) {
    std::wstring s(szStr);

    if (std::find_if(s.begin(), s.end(), [](wchar_t c) { return !std::isxdigit(static_cast<unsigned char>(c)); }) ==
        s.end())
        return TRUE;
    else
        return FALSE;
}

WCHAR* get_username() {
    WCHAR *username;
    DWORD nSize = (UNLEN + 1) * 2;

    username = (WCHAR *) malloc(nSize * sizeof(WCHAR));
    if (!username) {
        return NULL;
    }
    if (0 == GetUserNameW(username, &nSize)) {
        free(username);
        return NULL;
    }
    return username;
}

void IncreaseSizeOfImage() {
    PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY) pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
    PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY,
                                                         Reserved1[0] /*InLoadOrderLinks*/);
    PULONG pEntrySizeOfImage = (PULONG) &tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
    *pEntrySizeOfImage = (ULONG) ((INT_PTR) tableEntry->DllBase + 0x100000);
}

void ErasePEHeader() {
    DWORD OldProtect = 0;
    char *pBaseAddr = (char *) GetModuleHandle(NULL);
    VirtualProtect(pBaseAddr, 4096, PAGE_READWRITE, &OldProtect);
    SecureZeroMemory(pBaseAddr, 4096);
}

bool CheckVMModules() {
    /* Some vars */
    HMODULE hDll;

    /* Array of strings of blacklisted dlls */
    CONST WCHAR *szDlls[] = {
            L"avghookx.dll",        // AVG
            L"avghooka.dll",        // AVG
            L"snxhk.dll",        // Avast
            L"sbiedll.dll",        // Sandboxie
            L"dbghelp.dll",        // WindBG
            L"api_log.dll",        // iDefense Lab
            L"dir_watch.dll",    // iDefense Lab
            L"pstorec.dll",        // SunBelt Sandbox
            L"vmcheck.dll",        // Virtual PC
            L"wpespy.dll",        // WPE Pro
            L"cmdvrt64.dll",        // Comodo Container
            L"cmdvrt32.dll",        // Comodo Container

    };

    WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
    for (int i = 0; i < dwlength; i++) {
        hDll = GetModuleHandleW(szDlls[i]);
        if (hDll == NULL) {
            continue;
        } else {
            return true;
        }
    }
    return false;
}

bool CheckKnownFileNames() {

    /* Array of strings of filenames seen in sandboxes */
    CONST WCHAR *szFilenames[] = {
            L"sample.exe",
            L"bot.exe",
            L"sandbox.exe",
            L"malware.exe",
            L"test.exe",
            L"klavme.exe",
            L"myapp.exe",
            L"testapp.exe",

    };

    if (!pPeb->ProcessParameters->ImagePathName.Buffer) {
        return false;
    }
    WCHAR *szFileName = PathFindFileNameW(pPeb->ProcessParameters->ImagePathName.Buffer);

    WORD dwlength = sizeof(szFilenames) / sizeof(szFilenames[0]);
    for (int i = 0; i < dwlength; i++) {
        if (StrCmpIW(szFilenames[i], szFileName) != 0) {
            continue;
        } else {
            return true;
        }
    }
    PathRemoveExtensionW(szFileName);
    if ((wcslen(szFileName) == 32 || wcslen(szFileName) == 40 || wcslen(szFileName) == 64) && IsHexString(szFileName)) {
        return true;
    } else {
        return false;
    }
}

bool CheckKnownUsernames() {
    CONST WCHAR* szUsernames[] = {
            L"CurrentUser",
            L"Sandbox",
            L"Emily",
            L"HAPUBWS",
            L"Hong Lee",
            L"IT-ADMIN",
            L"Johnson",
            L"Miller",
            L"milozs",
            L"Peter Wilson",
            L"timmy",
            L"user",
            L"sand box",
            L"malware",
            L"maltest",
            L"test user",
            L"virus",
            L"John Doe",
    };
    WCHAR *username;

    if (NULL == (username = get_username())) {
        return false;
    }
    WORD dwlength = sizeof(szUsernames) / sizeof(szUsernames[0]);
    for (int i = 0; i < dwlength; i++) {
        BOOL matched = FALSE;
        if (0 == _wcsicmp(szUsernames[i], username)) {
            matched = TRUE;
        }
        if (matched) {
            return true;
        } else {
            continue;
        }
    }
    free(username);
    return false;
}

void InitSecurity() {
    IncreaseSizeOfImage();
    ErasePEHeader();
    if (CheckVMModules()) {
        std::cout << "VM Found - Modules" << std::endl;
    }
    if (CheckKnownFileNames()) {
        std::cout << "VM Found - File Names" << std::endl;
    }
    if (CheckKnownUsernames()) {
        std::cout << "VM Found - User Names" << std::endl;
    }
}

int main() {
    InitSecurity();
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
