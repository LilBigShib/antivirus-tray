#include "service_install.h"
#include "service_shared.h"
#include <sddl.h>

DWORD InstallService()
{
    std::wstring path = SiblingExecutablePath(L"AntivirusService.exe");
    const std::wstring application = SiblingExecutablePath(L"AntivirusTray.exe");
    if (path.empty() || application.empty())
        return ERROR_BAD_PATHNAME;
    const DWORD attributes = GetFileAttributesW(application.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return ERROR_FILE_NOT_FOUND;
    path = L"\"" + path + L"\"";

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (manager == nullptr)
        return GetLastError();
    SC_HANDLE service = CreateServiceW(manager, SERVICE_NAME, L"Antivirus Service",
        WRITE_DAC | DELETE, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    const DWORD createError = service == nullptr ? GetLastError() : ERROR_SUCCESS;
    CloseServiceHandle(manager);
    if (service == nullptr)
        return createError;

    // Обычным пользователям разрешены проверка состояния и запуск; остановка идёт через RPC.
    PSECURITY_DESCRIPTOR security = nullptr;
    DWORD error = ERROR_SUCCESS;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;AU)",
            SDDL_REVISION_1, &security, nullptr))
        error = GetLastError();
    else
    {
        if (!SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, security))
            error = GetLastError();
        LocalFree(security);
    }
    if (error != ERROR_SUCCESS)
        DeleteService(service);
    CloseServiceHandle(service);
    return error;
}

DWORD UninstallService()
{
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr)
        return GetLastError();
    SC_HANDLE service = OpenServiceW(manager, SERVICE_NAME, DELETE | SERVICE_QUERY_STATUS);
    const DWORD openError = service == nullptr ? GetLastError() : ERROR_SUCCESS;
    CloseServiceHandle(manager);
    if (service == nullptr)
        return openError;

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    DWORD error = ERROR_SUCCESS;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<BYTE *>(&status), sizeof(status), &bytesNeeded))
        error = GetLastError();
    else if (status.dwCurrentState != SERVICE_STOPPED)
        error = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
    else if (!DeleteService(service))
        error = GetLastError();
    CloseServiceHandle(service);
    return error;
}
