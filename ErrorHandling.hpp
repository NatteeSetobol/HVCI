#ifndef ___ERROR_HANDLING___
#define ___ERROR_HANDLING___

#include <stdexcept>
#include <windows.h>
#include <stdio.h>

void ThrowError(char* reason);
void ShowError();

#endif