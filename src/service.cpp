#include "service_shared.h"
#include "service_install.h"
#include "antivirus_rpc.h"
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <iostream>
#include <vector>

struct ApplicationProcess
{
    DWORD sessionId;
    HANDLE process;
    HANDLE exitEvent;
};

SERVICE_STATUS_HANDLE serviceStatusHandle = nullptr;
HANDLE sessionsChanged = nullptr;
HANDLE workerStop = nullptr;
HANDLE applicationJob = nullptr;
std::vector<ApplicationProcess> applications;

void LogError(const wchar_t *operation, DWORD error)
{
    HANDLE log = RegisterEventSourceW(nullptr, SERVICE_NAME);
    if (log == nullptr)
        return;
    const std::wstring code = std::to_wstring(error);
    const wchar_t *strings[] = {operation, code.c_str()};
    ReportEventW(log, EVENTLOG_ERROR_TYPE, 0, 1, nullptr, 2, 0, strings, nullptr);
    DeregisterEventSource(log);
}

void ReportStatus(DWORD state, DWORD error = ERROR_SUCCESS)
{
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwWin32ExitCode = error;
    if (state == SERVICE_RUNNING)
        status.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
    {
        status.dwCheckPoint = 1;
        status.dwWaitHint = 10000;
    }
    if (!SetServiceStatus(serviceStatusHandle, &status))
        LogError(L"Обновление состояния службы", GetLastError());
}

DWORD WINAPI ServiceControl(DWORD control, DWORD eventType, void *, void *)
{
    if (control == SERVICE_CONTROL_INTERROGATE)
        return NO_ERROR;
    if (control == SERVICE_CONTROL_SESSIONCHANGE)
    {
        if (eventType == WTS_SESSION_LOGON || eventType == WTS_CONSOLE_CONNECT ||
            eventType == WTS_REMOTE_CONNECT)
            SetEvent(sessionsChanged);
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

HANDLE CreateExitEvent(DWORD processId)
{
    PSECURITY_DESCRIPTOR security = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;AU)",
            SDDL_REVISION_1, &security, nullptr))
        return nullptr;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security, FALSE};
    const std::wstring name = ExitEventName(processId);
    HANDLE event = CreateEventW(&attributes, TRUE, FALSE, name.c_str());
    const DWORD error = GetLastError();
    LocalFree(security);
    if (event != nullptr && error == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(event);
        event = nullptr;
    }
    if (event == nullptr)
        SetLastError(error);
    return event;
}

bool SessionHasApplication(DWORD sessionId)
{
    for (auto iterator = applications.begin(); iterator != applications.end();)
    {
        if (WaitForSingleObject(iterator->process, 0) == WAIT_OBJECT_0)
        {
            CloseHandle(iterator->process);
            CloseHandle(iterator->exitEvent);
            iterator = applications.erase(iterator);
        }
        else
        {
            if (iterator->sessionId == sessionId)
                return true;
            ++iterator;
        }
    }
    return false;
}

bool StartSessionApplication(DWORD sessionId, const std::wstring &path)
{
    HANDLE token = nullptr;
    if (!WTSQueryUserToken(sessionId, &token))
    {
        LogError(L"Получение токена пользователя", GetLastError());
        return false;
    }
    void *environment = nullptr;
    if (!CreateEnvironmentBlock(&environment, token, FALSE))
    {
        LogError(L"Создание окружения пользователя", GetLastError());
        CloseHandle(token);
        return false;
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    wchar_t desktop[] = L"winsta0\\default";
    startup.lpDesktop = desktop;
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + path + L"\" --hidden";
    std::wstring directory = path.substr(0, path.find_last_of(L"\\/"));

    // Сначала создаём процесс приостановленным, чтобы подготовить сигнал выхода и группу процессов.
    const BOOL created = CreateProcessAsUserW(token, path.c_str(), command.data(),
        nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
        environment, directory.c_str(), &startup, &process);
    DWORD error = created ? ERROR_SUCCESS : GetLastError();
    DestroyEnvironmentBlock(environment);
    CloseHandle(token);
    if (!created)
    {
        LogError(L"Запуск графического приложения", error);
        return false;
    }

    HANDLE exitEvent = CreateExitEvent(process.dwProcessId);
    if (exitEvent == nullptr)
        error = GetLastError();
    else if (!AssignProcessToJobObject(applicationJob, process.hProcess))
        error = GetLastError();
    else if (ResumeThread(process.hThread) == static_cast<DWORD>(-1))
        error = GetLastError();
    CloseHandle(process.hThread);

    if (error != ERROR_SUCCESS)
    {
        TerminateProcess(process.hProcess, error);
        CloseHandle(process.hProcess);
        if (exitEvent != nullptr)
            CloseHandle(exitEvent);
        LogError(L"Подготовка графического приложения", error);
        return false;
    }
    applications.push_back({sessionId, process.hProcess, exitEvent});
    return true;
}

bool StartApplicationsInSessions()
{
    WTS_SESSION_INFOW *sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count))
    {
        LogError(L"Получение списка сеансов", GetLastError());
        return false;
    }
    const std::wstring path = SiblingExecutablePath(L"AntivirusTray.exe");
    bool complete = !path.empty();
    for (DWORD index = 0; index < count && !path.empty(); ++index)
    {
        const DWORD sessionId = sessions[index].SessionId;
        if (sessionId == 0 || SessionHasApplication(sessionId))
            continue;

        wchar_t *userName = nullptr;
        DWORD bytes = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId,
                                       WTSUserName, &userName, &bytes))
        {
            const bool loggedOn = bytes > sizeof(wchar_t) && userName[0] != L'\0';
            WTSFreeMemory(userName);
            if (loggedOn && !StartSessionApplication(sessionId, path))
                complete = false;
        }
        else if (sessions[index].State == WTSActive || sessions[index].State == WTSDisconnected)
            complete = false;
    }
    WTSFreeMemory(sessions);
    return complete;
}

DWORD WINAPI SessionWorker(void *)
{
    HANDLE events[] = {workerStop, sessionsChanged};
    DWORD timeout = INFINITE;
    while (true)
    {
        const DWORD result = WaitForMultipleObjects(2, events, FALSE, timeout);
        if (result == WAIT_OBJECT_0)
            return 0;
        if (result == WAIT_FAILED)
        {
            LogError(L"Ожидание изменения сеансов", GetLastError());
            return 1;
        }
        // Повторяем неудачный запуск; при обычной работе ждём уведомлений Windows.
        timeout = StartApplicationsInSessions() ? INFINITE : 1000;
    }
}

void StopApplications()
{
    for (const auto &application : applications)
        SetEvent(application.exitEvent);
    const ULONGLONG deadline = GetTickCount64() + 5000;
    for (const auto &application : applications)
    {
        const ULONGLONG now = GetTickCount64();
        const DWORD timeout = now < deadline ? static_cast<DWORD>(deadline - now) : 0;
        if (WaitForSingleObject(application.process, timeout) != WAIT_OBJECT_0)
        {
            TerminateProcess(application.process, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(application.process, INFINITE);
        }
        CloseHandle(application.process);
        CloseHandle(application.exitEvent);
    }
    applications.clear();
}

RPC_STATUS RPC_ENTRY AllowLocalUser(RPC_IF_HANDLE, void *)
{
    const RPC_STATUS status = RpcImpersonateClient(nullptr);
    if (status != RPC_S_OK)
        return status;
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    BOOL member = FALSE;
    const BOOL allowed = CreateWellKnownSid(WinAuthenticatedUserSid, nullptr, sid, &size) &&
                         CheckTokenMembership(nullptr, sid, &member) && member;
    RpcRevertToSelf();
    return allowed ? RPC_S_OK : RPC_S_ACCESS_DENIED;
}

extern "C" unsigned long RequestServiceStop(handle_t)
{
    const RPC_STATUS status = RpcMgmtStopServerListening(nullptr);
    return status == RPC_S_NOT_LISTENING ? RPC_S_OK : status;
}

DWORD StartRpcServer()
{
    PSECURITY_DESCRIPTOR security = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
            SDDL_REVISION_1, &security, nullptr))
        return GetLastError();
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t *>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t *>(RPC_ENDPOINT)), security);
    LocalFree(security);
    if (status != RPC_S_OK)
        return status;
    status = RpcServerRegisterIfEx(AntivirusControl_v1_0_s_ifspec, nullptr, nullptr,
        RPC_IF_ALLOW_LOCAL_ONLY | RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT, AllowLocalUser);
    if (status != RPC_S_OK)
        return status;
    return RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
}

void WINAPI ServiceMain(DWORD, wchar_t **)
{
    serviceStatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceControl, nullptr);
    if (serviceStatusHandle == nullptr)
    {
        LogError(L"Регистрация обработчика службы", GetLastError());
        return;
    }
    ReportStatus(SERVICE_START_PENDING);

    DWORD error = ERROR_SUCCESS;
    sessionsChanged = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (sessionsChanged == nullptr)
        error = GetLastError();
    workerStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (workerStop == nullptr && error == ERROR_SUCCESS)
        error = GetLastError();
    applicationJob = CreateJobObjectW(nullptr, nullptr);
    if (applicationJob == nullptr && error == ERROR_SUCCESS)
        error = GetLastError();

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (error == ERROR_SUCCESS && !SetInformationJobObject(applicationJob,
            JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        error = GetLastError();
    if (error == ERROR_SUCCESS)
        error = StartRpcServer();

    HANDLE worker = nullptr;
    if (error == ERROR_SUCCESS)
    {
        worker = CreateThread(nullptr, 0, SessionWorker, nullptr, 0, nullptr);
        if (worker == nullptr)
            error = GetLastError();
    }
    if (error == ERROR_SUCCESS)
    {
        ReportStatus(SERVICE_RUNNING);
        SetEvent(sessionsChanged);
        error = RpcMgmtWaitServerListen();
        if (error == RPC_S_NOT_LISTENING)
            error = ERROR_SUCCESS;
    }

    ReportStatus(SERVICE_STOP_PENDING);
    if (worker != nullptr)
    {
        SetEvent(workerStop);
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
    }
    RpcMgmtStopServerListening(nullptr);
    // Дожидаемся возврата RPC-команды, прежде чем завершать отправившее её приложение.
    RpcServerUnregisterIf(AntivirusControl_v1_0_s_ifspec, nullptr, TRUE);
    StopApplications();
    if (applicationJob != nullptr) CloseHandle(applicationJob);
    if (workerStop != nullptr) CloseHandle(workerStop);
    if (sessionsChanged != nullptr) CloseHandle(sessionsChanged);
    if (error != ERROR_SUCCESS)
        LogError(L"Работа службы", error);
    ReportStatus(SERVICE_STOPPED, error);
}

int wmain(int argumentCount, wchar_t **arguments)
{
    if (argumentCount == 2)
    {
        DWORD error = ERROR_BAD_ARGUMENTS;
        if (lstrcmpW(arguments[1], L"--install") == 0)
            error = InstallService();
        else if (lstrcmpW(arguments[1], L"--uninstall") == 0)
            error = UninstallService();
        else
        {
            std::wcerr << L"Использование: AntivirusService.exe [--install | --uninstall]\n";
            return static_cast<int>(error);
        }
        if (error == ERROR_SUCCESS)
            std::wcout << L"Операция выполнена.\n";
        else
            std::wcerr << L"Ошибка: " << error << L". Установка и удаление требуют прав администратора."
                       << L" Перед удалением остановите службу через меню приложения.\n";
        return static_cast<int>(error);
    }
    if (argumentCount != 1)
        return ERROR_BAD_ARGUMENTS;

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<wchar_t *>(SERVICE_NAME), ServiceMain},
        {nullptr, nullptr}
    };
    if (!StartServiceCtrlDispatcherW(table))
    {
        const DWORD error = GetLastError();
        std::wcerr << L"Службу нужно установить через --install и запускать через AntivirusTray.exe."
                   << L" Код ошибки: " << error << L"\n";
        return static_cast<int>(error);
    }
    return 0;
}
