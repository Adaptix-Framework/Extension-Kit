cmake_minimum_required(VERSION 3.16)
#project(Process-BOF C)

set(CMAKE_C_STANDARD 99)

# Include directories (main _include is at root level)
include_directories(
    ${CMAKE_SOURCE_DIR}/_include
#    ${CMAKE_CURRENT_SOURCE_DIR}/process
)

# Source files
set(FINDMODULE_SOURCES findobjects/FindModule.c)
set(FINDPROCHANDLE_SOURCES findobjects/FindProcHandle.c)
set(PSC_SOURCES process/psc.c)
set(PROCFREEZE_SOURCES procfreeze/procfreeze.c)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -w -Wno-incompatible-pointer-types -DBOF")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

# Object file targets
add_library(findmodule OBJECT ${FINDMODULE_SOURCES})
target_compile_options(findmodule PRIVATE -masm=intel)

add_library(findprochandle OBJECT ${FINDPROCHANDLE_SOURCES})
target_compile_options(findprochandle PRIVATE -masm=intel)

add_library(psc OBJECT ${PSC_SOURCES})
target_compile_options(psc PRIVATE -masm=intel)

add_library(procfreeze OBJECT ${PROCFREEZE_SOURCES})
target_compile_options(procfreeze PRIVATE -masm=intel)

# Create _bin directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/_bin)

# Custom commands to copy object files to _bin
add_custom_target(copy_findmodule ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:findmodule> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/findmodule.x64.o
    DEPENDS findmodule
    COMMENT "Copying findmodule object file"
)

add_custom_target(copy_findprochandle ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:findprochandle> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/findprochandle.x64.o
    DEPENDS findprochandle
    COMMENT "Copying findprochandle object file"
)

add_custom_target(copy_psc ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:psc> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/psc.x64.o
    DEPENDS psc
    COMMENT "Copying psc object file"
)

add_custom_target(copy_procfreeze ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:procfreeze> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/procfreeze.x64.o
    DEPENDS procfreeze
    COMMENT "Copying procfreeze object file"
)
