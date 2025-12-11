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


