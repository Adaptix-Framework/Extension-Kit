cmake_minimum_required(VERSION 3.16)
#project(Postex-BOF C)

set(CMAKE_C_STANDARD 99)

# Include directories (main _include is at root level)
include_directories(${CMAKE_SOURCE_DIR}/_include)

# Source files
set(SCREENSHOT_SOURCES ScreenshotBOF/entry.c)
set(ADDFIREWALLRULE_SOURCES firewallrule/addfirewallrule.c)
set(SAURONEYE_SOURCES SauronEyeBOF/entry.c)
set(EXITPROCESS_SOURCES exitprocess/exitprocess.c)
set(EXITTHREAD_SOURCES exitthread/exitthread.c)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -w -Wno-int-conversion -Wno-incompatible-pointer-types")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

# Object file targets
add_library(Screenshot OBJECT ${SCREENSHOT_SOURCES})
add_library(addfirewallrule OBJECT ${ADDFIREWALLRULE_SOURCES})
add_library(sauroneye OBJECT ${SAURONEYE_SOURCES})
add_library(exitprocess OBJECT ${EXITPROCESS_SOURCES})
add_library(exitthread OBJECT ${EXITTHREAD_SOURCES})

# Create _bin directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/_bin)

# Custom commands to copy object files to _bin
add_custom_target(copy_Screenshot ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:Screenshot> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/Screenshot.x64.o
    DEPENDS Screenshot
    COMMENT "Copying Screenshot object file"
)

add_custom_target(copy_addfirewallrule ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:addfirewallrule> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/addfirewallrule.x64.o
    DEPENDS addfirewallrule
    COMMENT "Copying addfirewallrule object file"
)

add_custom_target(copy_sauroneye ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:sauroneye> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/sauroneye.x64.o
    DEPENDS sauroneye
    COMMENT "Copying sauroneye object file"
)

add_custom_target(copy_exitprocess ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:exitprocess> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/exitprocess.x64.o
    DEPENDS exitprocess
    COMMENT "Copying exitprocess object file"
)

add_custom_target(copy_exitthread ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:exitthread> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/exitthread.x64.o
    DEPENDS exitthread
    COMMENT "Copying exitthread object file"
)
