#include "syscall.h"
#include <intrin.h>

SW2_SYSCALL_LIST SW2_SyscallList;

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW2_ROX8(Hash);
    }

    return Hash;
}

// Simple syscall implementation using the syscall instruction
// For this demo, we'll use the Windows API functions as fallback
// In a real implementation, you would use proper syscall stubs

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
 IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect)
{
    // Use the NtAllocateVirtualMemory from ntdll.dll
    typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
 IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN ULONG ZeroBits,
        IN OUT PSIZE_T RegionSize,
        IN ULONG AllocationType,
        IN ULONG Protect);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtAllocateVirtualMemory NtAllocateVirtualMemoryFunc = 
        (_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");

    if (!NtAllocateVirtualMemoryFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtAllocateVirtualMemoryFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

EXTERN_C NTSTATUS NtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
    typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
    IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN PVOID Buffer,
        IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtWriteVirtualMemory NtWriteVirtualMemoryFunc = 
        (_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    
    if (!NtWriteVirtualMemoryFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtWriteVirtualMemoryFunc(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

EXTERN_C NTSTATUS NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
    typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
  IN HANDLE ProcessHandle,
        IN PVOID StartRoutine,
        IN PVOID Argument OPTIONAL,
      IN ULONG CreateFlags,
        IN SIZE_T ZeroBits,
        IN SIZE_T StackSize,
        IN SIZE_T MaximumStackSize,
        IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtCreateThreadEx NtCreateThreadExFunc = 
    (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    if (!NtCreateThreadExFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtCreateThreadExFunc(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, 
    StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

EXTERN_C NTSTATUS NtClose(IN HANDLE Handle)
{
    typedef NTSTATUS(NTAPI* _NtClose)(IN HANDLE Handle);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtClose NtCloseFunc = (_NtClose)GetProcAddress(hNtdll, "NtClose");
    
    if (!NtCloseFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtCloseFunc(Handle);
}

EXTERN_C NTSTATUS NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType)
{
    typedef NTSTATUS(NTAPI* _NtFreeVirtualMemory)(
  IN HANDLE ProcessHandle,
IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
        IN ULONG FreeType);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtFreeVirtualMemory NtFreeVirtualMemoryFunc = 
   (_NtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");
    
    if (!NtFreeVirtualMemoryFunc) return STATUS_PROCEDURE_NOT_FOUND;

  return NtFreeVirtualMemoryFunc(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

// Additional syscall implementations for process creation evasion
EXTERN_C NTSTATUS NtCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL)
{
    typedef NTSTATUS(NTAPI* _NtCreateProcess)(
     OUT PHANDLE ProcessHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ParentProcess,
      IN BOOLEAN InheritObjectTable,
        IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
IN HANDLE ExceptionPort OPTIONAL);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

  _NtCreateProcess NtCreateProcessFunc = 
 (_NtCreateProcess)GetProcAddress(hNtdll, "NtCreateProcess");
    
    if (!NtCreateProcessFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtCreateProcessFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, 
        InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}

EXTERN_C NTSTATUS NtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
  IN HANDLE FileHandle OPTIONAL)
{
    typedef NTSTATUS(NTAPI* _NtCreateSection)(
  OUT PHANDLE SectionHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN PLARGE_INTEGER MaximumSize OPTIONAL,
 IN ULONG SectionPageProtection,
        IN ULONG AllocationAttributes,
        IN HANDLE FileHandle OPTIONAL);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtCreateSection NtCreateSectionFunc = 
        (_NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
 
    if (!NtCreateSectionFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtCreateSectionFunc(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, 
        SectionPageProtection, AllocationAttributes, FileHandle);
}

EXTERN_C NTSTATUS NtOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
  IN ULONG OpenOptions)
{
    typedef NTSTATUS(NTAPI* _NtOpenFile)(
    OUT PHANDLE FileHandle,
        IN ACCESS_MASK DesiredAccess,
      IN POBJECT_ATTRIBUTES ObjectAttributes,
        OUT PIO_STATUS_BLOCK IoStatusBlock,
 IN ULONG ShareAccess,
        IN ULONG OpenOptions);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    _NtOpenFile NtOpenFileFunc = 
        (_NtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
    
    if (!NtOpenFileFunc) return STATUS_PROCEDURE_NOT_FOUND;

    return NtOpenFileFunc(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, 
        ShareAccess, OpenOptions);
}
