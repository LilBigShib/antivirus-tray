cmake_minimum_required(VERSION 3.20)
project(AntivirusTray LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Приложение нужно собирать для Windows.")
endif()

add_executable(AntivirusTray WIN32 src/main.cpp)
target_compile_features(AntivirusTray PRIVATE cxx_std_17)
target_compile_definitions(AntivirusTray PRIVATE UNICODE _UNICODE)
target_link_libraries(AntivirusTray PRIVATE user32 shell32 advapi32)

if(MSVC)
    target_compile_options(AntivirusTray PRIVATE /W4 /utf-8)
    # Встраиваем среду выполнения C++, чтобы не переносить её DLL рядом с EXE.
    set_property(TARGET AntivirusTray PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(MINGW)
    target_compile_options(AntivirusTray PRIVATE -Wall -Wextra -Wpedantic)
    target_link_options(AntivirusTray PRIVATE -municode -static)
endif()

install(TARGETS AntivirusTray RUNTIME DESTINATION .)
