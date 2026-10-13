#include "service_client.h"
#include "service_shared.h"
#include "antivirus_rpc.h"
#include <tlhelp32.h>

namespace
{
    bool QueryStatus(SC_HANDLE service, SERVICE_STATUS_PROCESS &status, DWORD &error)
    {
        DWORD bytesNeeded = 0;
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<BYTE *>(&status), sizeof(status),
                                 &bytesNeeded))
            return true;
        error = GetLastError();
        return false;
    }

    bool WaitForState(SC_HANDLE service, DWORD desiredState,
                      SERVICE_STATUS_PROCESS &status, DWORD &error)
    {
        const ULONGLONG deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline)
        {
            if (!QueryStatus(service, status, error))
                return false;
            if (status.dwCurrentState == desiredState)
                return true;
            if (desiredState == SERVICE_RUNNING && status.dwCurrentState == SERVICE_STOPPED)
            {
                error = status.dwWin32ExitCode != 0 ? status.dwWin32ExitCode
                                                  : ERROR_SERVICE_NOT_ACTIVE;
                return false;
            }
            Sleep(200);
        }
        error = ERROR_TIMEOUT;
        return false;
    }

    bool HasServiceParent(DWORD serviceProcessId, DWORD &error)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            error = GetLastError();
            return false;
        }
        PROCESSENTRY32W process{};
        process.dwSize = sizeof(process);
        bool found = false;
        bool validParent = false;
        if (Process32FirstW(snapshot, &process))
        {
            do
            {
                if (process.th32ProcessID == GetCurrentProcessId())
                {
                    found = true;
                    validParent = process.th32ParentProcessID == serviceProcessId;
                    break;
                }
            } while (Process32NextW(snapshot, &process));
        }
        if (!found)
            error = ERROR_NOT_FOUND;
        CloseHandle(snapshot);
        return validParent;
    }
}

StartupAction CheckServiceStartup(DWORD &error)
{
    error = ERROR_SUCCESS;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr)
    {
        error = GetLastError();
        return StartupAction::Error;
    }
    SC_HANDLE service = OpenServiceW(manager, SERVICE_NAME,
                                    SERVICE_QUERY_STATUS | SERVICE_START);
    const DWORD openError = service == nullptr ? GetLastError() : ERROR_SUCCESS;
    CloseServiceHandle(manager);
    if (service == nullptr)
    {
        error = openError;
        return StartupAction::Error;
    }

    SERVICE_STATUS_PROCESS status{};
    bool ready = QueryStatus(service, status, error);
    if (ready && status.dwCurrentState == SERVICE_STOP_PENDING)
        ready = WaitForState(service, SERVICE_STOPPED, status, error);

    bool startedHere = false;
    if (ready && status.dwCurrentState == SERVICE_STOPPED)
    {
        startedHere = true;
        if (!StartServiceW(service, 0, nullptr))
        {
            error = GetLastError();
            ready = error == ERROR_SERVICE_ALREADY_RUNNING;
            if (ready)
                error = ERROR_SUCCESS;
        }
    }
    if (ready)
        ready = WaitForState(service, SERVICE_RUNNING, status, error);
    CloseServiceHandle(service);
    if (!ready)
        return StartupAction::Error;

    // Запустивший службу экземпляр уступает место приложениям, созданным самой службой.
    if (startedHere)
        return StartupAction::Exit;
    const bool validParent = HasServiceParent(status.dwProcessId, error);
    if (error != ERROR_SUCCESS)
        return StartupAction::Error;
    return validParent ? StartupAction::Run : StartupAction::Exit;
}

DWORD StopServiceThroughRpc()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;
    RPC_STATUS status = RpcStringBindingComposeW(nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t *>(L"ncalrpc")), nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t *>(RPC_ENDPOINT)), nullptr,
        &stringBinding);
    if (status != RPC_S_OK)
        return status;
    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);
    if (status != RPC_S_OK)
        return status;

    // Ошибки соединения RPC передаёт как исключения Windows.
    RpcTryExcept
    {
        status = RequestServiceStop(binding);
    }
    RpcExcept(1)
    {
        status = RpcExceptionCode();
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return status;
}
