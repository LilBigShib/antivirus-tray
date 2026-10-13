#pragma once

#include <windows.h>
#include <string>

inline constexpr wchar_t SERVICE_NAME[] = L"AntivirusService";
inline constexpr wchar_t RPC_ENDPOINT[] = L"AntivirusService.Control";

inline std::wstring ExitEventName(DWORD processId)
{
    return L"Global\\AntivirusTray.Exit." + std::to_wstring(processId);
}

inline std::wstring SiblingExecutablePath(const wchar_t *fileName)
{
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(),
                                          static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size())
        return {};
    path.resize(length);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos)
        return {};
    path.resize(separator + 1);
    return path + fileName;
}
