#include "ErrorHandling.hpp"

void ThrowError(char* reason)
{
    throw std::runtime_error(reason);
}

void ShowError()
{
    DWORD errorCode = GetLastError();

    LPSTR errorMessageBuffer = nullptr;
    DWORD messageSize = FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    reinterpret_cast<LPSTR>(&errorMessageBuffer), 0, NULL);
    printf("[-] %s", errorMessageBuffer);
}
