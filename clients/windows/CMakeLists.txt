option(CLI_OVPN3 "Build ${PROJECT_NAME} with OpenVPN3 support" OFF)

cmake_minimum_required(VERSION 3.10)

project(openvpn-gui C CXX)

add_executable(${PROJECT_NAME} WIN32
    access.c
    echo.c
    env_set.c
    localization.c
    main.c
    manage.c
    misc.c
    openvpn.c
    openvpn_config.c
    options.c
    proxy.c
    registry.c
    save_pass.c
    scripts.c
    service.c
    tray.c
    viewlog.c
    as.c
    pkcs11.c
    config_parser.c
    qr.c
    qrcodegen/qrcodegen.c
    res/openvpn-gui-res.rc
)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
# 2026-10-02 modsafe 分支：MSVC 专属参数按编译器分支（MinGW 会把 /flag 当输入文件报错）
if (MSVC)
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} /guard:cf /Qspectre")
else ()
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2")
endif ()

list(APPEND CMAKE_CONFIGURATION_TYPES Asan)

if (NOT MSVC)
    # MinGW 路径：跳过 MSVC 专属 Asan/CET 配置；基线加固用 ld 等价项；
    # _tWinMain 在 UNICODE 下展开为 wWinMain，MinGW 需 -municode 入口（否则 crt 找 WinMain 失败）
    set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -Wl,--nxcompat -Wl,--dynamicbase -municode")
else ()
set(CMAKE_C_FLAGS_ASAN
    "${CMAKE_C_FLAGS_DEBUG} /fsanitize=address" CACHE STRING
    "Flags used by the C compiler during AddressSanitizer builds." FORCE)

set(CMAKE_EXE_LINKER_FLAGS_ASAN
    "${CMAKE_EXE_LINKER_FLAGS_DEBUG}" CACHE STRING
    "Flags used by the linker during AddressSanitizer builds." FORCE)

set(CMAKE_SHARED_LINKER_FLAGS_ASAN
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}" CACHE STRING
    "Flags used by the linker during AddressSanitizer builds." FORCE)

set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /guard:cf /DYNAMICBASE")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /wd4996 /wd4267 /wd4244")

if(NOT (${CMAKE_C_COMPILER_ARCHITECTURE_ID} STREQUAL "ARM64"))
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /CETCOMPAT")
endif()
endif ()

target_link_libraries(${PROJECT_NAME} PRIVATE
    Wtsapi32.lib
    Netapi32.lib
    ws2_32.lib
    Winhttp.lib
    Secur32.lib
    Comctl32.lib
    Crypt32.lib
    Shlwapi.lib
    Advapi32.lib
    Shell32.lib
    Gdi32.lib
    Comdlg32.lib
    Ole32.lib
    Cryptui.lib
    Wininet.lib
    Iphlpapi.lib
    Ntdll.lib)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
    set(CMAKE_RC_FLAGS "/D \"HAVE_CONFIG_H\" /D \"_MSC_VER\"")
else ()
    # MinGW：windres 用 -D 形式；无 /MANIFEST 语义（无副作用）
    set(CMAKE_RC_FLAGS "-DHAVE_CONFIG_H -D_MSC_VER")
endif ()

# 2026-10-02 modsafe 分支：MinGW 无 mc.exe（MSVC SDK 工具）——eventmsg.mc 仅定义
# EVT_TEXT_2=1（事件日志文本 ID），MinGW 直接生成等价头文件，事件日志消息模板随系统默认降级
if (MSVC)
    add_custom_command(
        OUTPUT  eventmsg.h
        COMMAND mc.exe ${CMAKE_CURRENT_SOURCE_DIR}/eventmsg.mc -r ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/eventmsg.mc
        VERBATIM
        )
    add_custom_target(msg_header_gen ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/eventmsg.h)
    add_dependencies(${PROJECT_NAME} msg_header_gen)
else ()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/eventmsg.h" "#define EVT_TEXT_2 1\n")
endif ()

function(get_version_from_configure regex_arg ret)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/configure.ac" VERSION_STR REGEX ${regex_arg})
    string(REGEX MATCH ${regex_arg} VERSION_STR "${VERSION_STR}")
    set("${ret}" ${CMAKE_MATCH_1} PARENT_SCOPE)
endfunction()

get_version_from_configure("_GUI_VERSION_MAJOR\\], \\[([0-9]+)\\]" GUI_VERSION_MAJOR)
get_version_from_configure("_GUI_VERSION_MINOR\\], \\[([0-9]+)\\]" GUI_VERSION_MINOR)

configure_file(config-msvc.h.in config.h)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    _UNICODE
    UNICODE
    WIN32_LEAN_AND_MEAN
    HAVE_CONFIG_H)

if (${CLI_OVPN3})
    find_package(json-c REQUIRED)

    target_link_libraries(${PROJECT_NAME} PRIVATE
        json-c::json-c)

    target_compile_definitions(${PROJECT_NAME} PRIVATE
        ENABLE_OVPN3)
endif ()

if (NOT PROJECT_NAME_PLAP)
    set(PROJECT_NAME_PLAP "libopenvpn_plap")
endif()

add_library(${PROJECT_NAME_PLAP} SHARED
    localization.c
    manage.c
    misc.c
    openvpn.c
    openvpn_config.c
    options.c
    proxy.c
    pkcs11.c
    registry.c
    config_parser.c
    service.c
    qr.c
    qrcodegen/qrcodegen.c
    plap/ui_glue.c
    plap/stub.c
    plap/plap_common.c
    plap/plap_provider.c
    plap/plap_connection.c
    plap/plap_dll.c
    plap/openvpn_plap.def
    plap/openvpn-plap-res.rc)

target_link_libraries(${PROJECT_NAME_PLAP} PRIVATE
    ws2_32.lib
    Comctl32.lib
    Winhttp.lib
    Crypt32.lib
    Ole32.lib
    Shlwapi.lib
    Secur32.lib
    Gdi32.lib
    Cryptui.lib
    Rpcrt4.lib
    Iphlpapi.lib
    Ntdll.lib)

if (MSVC)
    add_dependencies(${PROJECT_NAME_PLAP} msg_header_gen)
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO")
endif ()
target_include_directories(${PROJECT_NAME_PLAP} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
target_compile_definitions(${PROJECT_NAME_PLAP} PRIVATE
    _UNICODE
    UNICODE
    WIN32_LEAN_AND_MEAN
    HAVE_CONFIG_H)

if (NOT TEST_PLAP_EXE)
    set(TEST_PLAP_EXE "test_plap")
endif()

add_executable(${TEST_PLAP_EXE}
    plap/test_plap.cpp
    plap/plap_common.c)

target_link_libraries(${TEST_PLAP_EXE} PRIVATE
    Rpcrt4
    Ole32
    Shlwapi
    Gdi32)

target_include_directories(${TEST_PLAP_EXE} PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
target_compile_definitions(${TEST_PLAP_EXE} PRIVATE
    _UNICODE
    UNICODE
    WIN32_LEAN_AND_MEAN
    HAVE_CONFIG_H)

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:Release>:/Zi>")
    target_link_options(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Release>:/DEBUG:FULL>"
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>")
else ()
    # MinGW：等价 Release 调试与裁剪选项
    target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:Release>:-g>")
    target_link_options(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Release>:-Wl,--gc-sections>")
endif ()

if (MSVC)
    target_link_options(${TEST_PLAP_EXE} PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTINPUT:${CMAKE_SOURCE_DIR}/plap/test-plap.manifest")
endif ()
