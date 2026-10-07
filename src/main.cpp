#include <windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <string>

constexpr UINT ID_OPEN = 1001;
constexpr UINT ID_EXIT = 1002;
constexpr wchar_t WINDOW_CLASS_NAME[] = L"AntivirusTrayWindow";

constexpr UINT WM_TRAYICON = WM_APP + 1;
constexpr UINT TRAY_ICON_ID = 1;
constexpr UINT_PTR TRAY_RETRY_TIMER = 1;

NOTIFYICONDATAW trayIcon{};
bool trayIconAdded = false;
UINT taskbarCreatedMessage = 0;

HANDLE CreateUserMutex(bool& alreadyRunning) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return nullptr;

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        CloseHandle(token);
        return nullptr;
    }

    // Размер сведений о пользователе определяет Windows, поэтому сначала запрашиваем его.
    auto* user = static_cast<TOKEN_USER*>(LocalAlloc(LPTR, size));
    if (user == nullptr) {
        CloseHandle(token);
        return nullptr;
    }
    const BOOL received = GetTokenInformation(token, TokenUser, user, size, &size);
    CloseHandle(token);
    if (!received) {
        LocalFree(user);
        return nullptr;
    }

    LPWSTR sid = nullptr;
    const BOOL converted = ConvertSidToStringSidW(user->User.Sid, &sid);
    LocalFree(user);
    if (!converted) return nullptr;

    const std::wstring name = std::wstring(L"Global\\AntivirusTray.") + sid;
    LocalFree(sid);

    // SID разделяет пользователей, а Global охватывает разные сеансы одного пользователя.
    HANDLE mutex = CreateMutexW(nullptr, FALSE, name.c_str());
    alreadyRunning = mutex != nullptr && GetLastError() == ERROR_ALREADY_EXISTS;
    return mutex;
}

bool AddTrayIcon(HWND window) {
    if (trayIconAdded) return true;
    trayIcon.cbSize = sizeof(trayIcon);
    trayIcon.hWnd = window;
    trayIcon.uID = TRAY_ICON_ID;
    trayIcon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    trayIcon.uCallbackMessage = WM_TRAYICON;
    trayIcon.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    lstrcpynW(trayIcon.szTip, L"Antivirus — учебный проект",
        static_cast<int>(ARRAYSIZE(trayIcon.szTip)));

    if (trayIcon.hIcon == nullptr || !Shell_NotifyIconW(NIM_ADD, &trayIcon)) {
        return false;
    }

    trayIcon.uVersion = NOTIFYICON_VERSION_4;
    if (!Shell_NotifyIconW(NIM_SETVERSION, &trayIcon)) {
        Shell_NotifyIconW(NIM_DELETE, &trayIcon);
        return false;
    }

    trayIconAdded = true;
    return true;
}

bool EnsureTrayIcon(HWND window) {
    if (AddTrayIcon(window)) {
        KillTimer(window, TRAY_RETRY_TIMER);
        return true;
    }
    return SetTimer(window, TRAY_RETRY_TIMER, 1000, nullptr) != 0;
}

void RemoveTrayIcon() {
    KillTimer(trayIcon.hWnd, TRAY_RETRY_TIMER);
    if (trayIconAdded) {
        Shell_NotifyIconW(NIM_DELETE, &trayIcon);
        trayIconAdded = false;
    }
}

void ShowMainWindow(HWND window) {
    if (IsIconic(window)) {
        ShowWindow(window, SW_RESTORE);
    } else {
        ShowWindow(window, SW_SHOW);
    }
    SetForegroundWindow(window);
}

void ShowTrayMenu(HWND window) {
    POINT position{};
    if (!GetCursorPos(&position)) return;

    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) return;

    if (!AppendMenuW(menu, MF_STRING, ID_OPEN, L"Открыть") ||
        !AppendMenuW(menu, MF_STRING, ID_EXIT, L"Выход")) {
        DestroyMenu(menu);
        return;
    }

    // Без этого меню трея может не закрыться при клике за его пределами.
    SetForegroundWindow(window);
    const UINT command = static_cast<UINT>(TrackPopupMenu(menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
        position.x, position.y, 0, window, nullptr));

    // Пустое сообщение предотвращает мгновенное закрытие меню при повторном открытии.
    PostMessageW(window, WM_NULL, 0, 0);
    DestroyMenu(menu);

    if (command != 0) {
        PostMessageW(window, WM_COMMAND, command, 0);
    } else if (trayIconAdded) {
        Shell_NotifyIconW(NIM_SETFOCUS, &trayIcon);
    }
}

HMENU CreateMainMenu() {
    HMENU mainMenu = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    if (mainMenu == nullptr || fileMenu == nullptr) {
        if (mainMenu != nullptr) DestroyMenu(mainMenu);
        if (fileMenu != nullptr) DestroyMenu(fileMenu);
        return nullptr;
    }

    if (!AppendMenuW(fileMenu, MF_STRING, ID_EXIT, L"Выход")) {
        DestroyMenu(fileMenu);
        DestroyMenu(mainMenu);
        return nullptr;
    }

    if (!AppendMenuW(mainMenu, MF_POPUP,
        reinterpret_cast<UINT_PTR>(fileMenu), L"Файл")) {
        DestroyMenu(fileMenu);
        DestroyMenu(mainMenu);
        return nullptr;
    }

    return mainMenu;
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    if (taskbarCreatedMessage != 0 && message == taskbarCreatedMessage) {
        RemoveTrayIcon();
        if (!EnsureTrayIcon(window)) {
            MessageBoxW(window, L"Не удалось запустить восстановление иконки.",
                L"Ошибка", MB_OK | MB_ICONERROR);
            DestroyWindow(window);
        }
        return 0;
    }

    switch (message) {
    case WM_TIMER:
        if (wParam == TRAY_RETRY_TIMER && AddTrayIcon(window)) {
            KillTimer(window, TRAY_RETRY_TIMER);
        }
        return 0;

    case WM_TRAYICON:
        // В версии 4 старшая часть lParam содержит номер иконки, младшая — событие.
        if (HIWORD(lParam) == TRAY_ICON_ID) {
            const UINT event = LOWORD(lParam);
            if (event == WM_LBUTTONUP || event == NIN_SELECT || event == NIN_KEYSELECT) {
                ShowMainWindow(window);
            } else if (event == WM_CONTEXTMENU) {
                ShowTrayMenu(window);
            }
        }
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_OPEN) {
            ShowMainWindow(window);
            return 0;
        }
        if (LOWORD(wParam) == ID_EXIT) {
            DestroyWindow(window);
            return 0;
        }
        break;

    case WM_CLOSE:
        ShowWindow(window, SW_HIDE);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;

    case WM_QUERYENDSESSION:
        return TRUE;

    case WM_ENDSESSION:
        if (wParam) DestroyWindow(window);
        return 0;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

int RunApplication(HINSTANCE instance, int showCommand, bool hidden) {
    taskbarCreatedMessage = RegisterWindowMessageW(L"TaskbarCreated");
    if (taskbarCreatedMessage == 0) {
        MessageBoxW(nullptr, L"Не удалось зарегистрировать сообщение панели задач.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = WINDOW_CLASS_NAME;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hbrBackground = GetSysColorBrush(COLOR_WINDOW);

    if (!RegisterClassW(&windowClass)) {
        MessageBoxW(nullptr, L"Не удалось зарегистрировать класс окна.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    HMENU mainMenu = CreateMainMenu();
    if (mainMenu == nullptr) {
        MessageBoxW(nullptr, L"Не удалось создать меню.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    HWND window = CreateWindowExW(
        0, WINDOW_CLASS_NAME, L"Antivirus",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 420,
        nullptr, mainMenu, instance, nullptr);

    if (window == nullptr) {
        DestroyMenu(mainMenu);
        MessageBoxW(nullptr, L"Не удалось создать главное окно.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    if (!EnsureTrayIcon(window)) {
        MessageBoxW(window, L"Не удалось запустить добавление иконки в область уведомлений.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        DestroyWindow(window);
        return 1;
    }

    if (!hidden) {
        ShowWindow(window, showCommand);
        UpdateWindow(window);
    }

    MSG message{};
    BOOL result = 0;
    while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    // GetMessage возвращает 0 при завершении и -1 при ошибке.
    if (result == -1) {
        MessageBoxW(window, L"Не удалось получить сообщение Windows.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        DestroyWindow(window);
        return 1;
    }

    return static_cast<int>(message.wParam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    int argumentCount = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argumentCount);
    if (arguments == nullptr) {
        MessageBoxW(nullptr, L"Не удалось прочитать параметры запуска.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }

    const bool hidden = argumentCount == 2 && lstrcmpW(arguments[1], L"--hidden") == 0;
    const bool valid = argumentCount == 1 || hidden;
    LocalFree(arguments);
    if (!valid) {
        MessageBoxW(nullptr, L"Запуск: AntivirusTray.exe [--hidden]\n"
            L"Параметр --hidden запускает программу без показа окна.",
            L"Неизвестный параметр", MB_OK | MB_ICONERROR);
        return 2;
    }

    bool alreadyRunning = false;
    HANDLE mutex = CreateUserMutex(alreadyRunning);
    if (mutex == nullptr) {
        MessageBoxW(nullptr, L"Не удалось проверить наличие другого экземпляра программы.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return 1;
    }
    if (alreadyRunning) {
        CloseHandle(mutex);
        return 0;
    }

    // Дескриптор остаётся открытым, пока работает приложение, включая скрытый режим.
    const int result = RunApplication(instance, showCommand, hidden);
    CloseHandle(mutex);
    return result;
}
