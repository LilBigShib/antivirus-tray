#pragma once

#include <windows.h>

enum class StartupAction
{
    Run,
    Exit,
    Error
};

StartupAction CheckServiceStartup(DWORD &error);
DWORD StopServiceThroughRpc();
