cmake_minimum_required(VERSION 3.20)
project(AntivirusTray LANGUAGES C CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Приложение нужно собирать для Windows.")
endif()

if(NOT MSVC)
    message(FATAL_ERROR "Для сборки RPC нужен MSVC и компилятор MIDL из Windows SDK.")
endif()

find_program(MIDL_EXECUTABLE midl
    HINTS "C:/Program Files (x86)/Windows Kits/10/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64"
    REQUIRED)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MIDL_PLATFORM x64)
else()
    set(MIDL_PLATFORM win32)
endif()

set(RPC_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/rpc")
set(RPC_HEADER "${RPC_DIRECTORY}/antivirus_rpc.h")
set(RPC_CLIENT "${RPC_DIRECTORY}/antivirus_rpc_c.c")
set(RPC_SERVER "${RPC_DIRECTORY}/antivirus_rpc_s.c")
file(MAKE_DIRECTORY "${RPC_DIRECTORY}")
add_custom_command(
    OUTPUT "${RPC_HEADER}" "${RPC_CLIENT}" "${RPC_SERVER}"
    COMMAND "${MIDL_EXECUTABLE}" /nologo /no_cpp /env ${MIDL_PLATFORM}
        /out "${RPC_DIRECTORY}" /h antivirus_rpc.h
        /cstub antivirus_rpc_c.c /sstub antivirus_rpc_s.c
        "${CMAKE_CURRENT_SOURCE_DIR}/rpc/service.idl"
    DEPENDS rpc/service.idl
    VERBATIM)
add_custom_target(GenerateRpc DEPENDS "${RPC_HEADER}" "${RPC_CLIENT}" "${RPC_SERVER}")

add_executable(AntivirusTray WIN32
    src/main.cpp src/service_client.cpp src/rpc_memory.cpp "${RPC_CLIENT}")
add_executable(AntivirusService
    src/service.cpp src/service_install.cpp src/rpc_memory.cpp "${RPC_SERVER}")

foreach(target AntivirusTray AntivirusService)
    add_dependencies(${target} GenerateRpc)
    target_include_directories(${target} PRIVATE "${RPC_DIRECTORY}")
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE)
    target_compile_options(${target} PRIVATE /W4 /utf-8)
    target_link_libraries(${target} PRIVATE advapi32 rpcrt4)
    # Встраиваем среду выполнения C++, чтобы не переносить её DLL рядом с EXE.
    set_property(TARGET ${target} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endforeach()
target_link_libraries(AntivirusTray PRIVATE user32 shell32)
target_link_libraries(AntivirusService PRIVATE wtsapi32 userenv)

install(TARGETS AntivirusTray AntivirusService RUNTIME DESTINATION .)
