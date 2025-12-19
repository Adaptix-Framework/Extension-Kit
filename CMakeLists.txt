cmake_minimum_required(VERSION 3.16)
project(ExtensionKit C)

set(CMAKE_C_STANDARD 99)

include_directories(
    /usr/x86_64-w64-mingw32/include

    ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/Kerbeus-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/SQL-BOF/common
    ${CMAKE_CURRENT_SOURCE_DIR}/Creds-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/Execution-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/LateralMovement-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/Postex-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/Process-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/SAL-BOF/_include
    ${CMAKE_CURRENT_SOURCE_DIR}/SAR-BOF/_include
)

file(GLOB_RECURSE EXTENSIONKIT_SOURCES
    AD-BOF/*.c
    Creds-BOF/*.c
    Elevation-BOF/*.c
    Execution-BOF/*.c
    Injection-BOF/*.c
    LateralMovement-BOF/*.c
    Postex-BOF/*.c
    Process-BOF/*.c
    SAL-BOF/*.c
    SAR-BOF/*.c
)

add_executable(extensionkit_dummy ${EXTENSIONKIT_SOURCES})

add_custom_target(all-make
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Running top-level Makefile in Extension-Kit"
)

add_custom_target(ad-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF
    COMMENT "Building AD-BOF via its Makefile"
)

add_custom_target(creds-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Creds-BOF
    COMMENT "Building Creds-BOF via its Makefile"
)

add_custom_target(elevation-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Elevation-BOF
    COMMENT "Building Elevation-BOF via its Makefile"
)

add_custom_target(execution-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Execution-BOF
    COMMENT "Building Execution-BOF via its Makefile"
)

add_custom_target(injection-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Injection-BOF
    COMMENT "Building Injection-BOF via its Makefile"
)

add_custom_target(lateralmovement-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/LateralMovement-BOF
    COMMENT "Building LateralMovement-BOF via its Makefile"
)

add_custom_target(postex-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Postex-BOF
    COMMENT "Building Postex-BOF via its Makefile"
)

add_custom_target(process-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Process-BOF
    COMMENT "Building Process-BOF via its Makefile"
)

add_custom_target(sal-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/SAL-BOF
    COMMENT "Building SAL-BOF via its Makefile"
)

add_custom_target(sar-bof
    COMMAND ${CMAKE_MAKE_PROGRAM}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/SAR-BOF
    COMMENT "Building SAR-BOF via its Makefile"
)
