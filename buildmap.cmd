@echo off
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
set "VS=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
set "PATH=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
cmake.exe -S . -B build-map -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_MAKE_PROGRAM="%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" -DENABLE_EXTENDED_HOOKS=OFF -DCMAKE_SHARED_LINKER_FLAGS=/MAP || exit /b 1
cmake.exe --build build-map || exit /b 1
