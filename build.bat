echo off
set OUTPUT=HVCI.exe
set MAIN_FILES=../main.cpp
set INCLUDES=../ErrorHandling.cpp ^

REM use ^ for line break

set FLAGS=/EHsc /Zi
set LIB_FILES=
set MACROS=-DDEBUG=1


if exist build (
    del build /Q
)

mkdir build
pushd build

cl.exe %FLAGS% /Fe:%OUTPUT% %MAIN_FILES% %INCLUDES% %MACROS%  %LIB_FILES%  


popd