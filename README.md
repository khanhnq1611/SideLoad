# SideLoad


- **Primary purpose:** Build the `SideLoad` DLL using Visual Studio; the code contains low-level syscall helper code and an entry point implementation.

Getting started

1. Open the solution `SideLoad.sln` in Visual Studio (recommended: Visual Studio 2019/2022).
2. Select the `x64` platform and the desired Configuration (`Debug` or `Release`).
3. Build the solution (Build -> Build Solution). The DLL and associated output will appear under the `x64\Debug` or `x64\Release` folders.

Important files

- `SideLoad/SideLoad.vcxproj` — Visual Studio project file.
- `SideLoad/dllmain.cpp` — DLL entry point and initialization code.
- `SideLoad/syscalls.c` and `SideLoad/syscall.h` — syscall wrappers and related helpers.
- `SideLoad/SideLoad.rc` and resource files — resources used by the DLL.

How the DLL works

- The DLL's entry point is implemented in `SideLoad/dllmain.cpp`. When the DLL is loaded into a process the `DllMain` routine runs initialization code (thread/process attach handling), sets up any runtime state, and registers or exposes the DLL's functionality.
- Low-level operations and direct syscall helpers live in `SideLoad/syscalls.c` and `SideLoad/syscall.h`; these are used by the DLL to perform privileged or low-level actions without relying on higher-level runtime wrappers.
- The built DLL exports its public functions (or performs in-process behavior) and runs inside the host process; use caution when loading or injecting native DLLs and ensure you understand the runtime effects.
- After it is  called and loaded by the process, it will create a new process and hollow it, so even when the process done, the defender will stuck to find where the malicious process exist 

