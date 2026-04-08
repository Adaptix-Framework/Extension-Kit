cmake_minimum_required(VERSION 3.16)
#project(FS-BOF C)

set(CMAKE_C_STANDARD 99)

# Include directories (main _include is at root level)
include_directories(${CMAKE_SOURCE_DIR}/_include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/_include)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -DBOF")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

# Create _bin directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/_bin)

# dir BOF target (migrated from SAL-BOF in Phase 2)
set(DIR_SOURCES dir/dir.c)

add_library(dir OBJECT ${DIR_SOURCES})

add_custom_target(copy_dir ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:dir> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/dir.x64.o
    DEPENDS dir
    COMMENT "Copying dir object file"
)

# type BOF target
set(TYPE_SOURCES type/type.c)
add_library(type OBJECT ${TYPE_SOURCES})
add_custom_target(copy_type ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:type> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/type.x64.o
    DEPENDS type
    COMMENT "Copying type object file"
)

# mkdir BOF target
set(MKDIR_SOURCES mkdir/mkdir.c)
add_library(mkdir OBJECT ${MKDIR_SOURCES})
add_custom_target(copy_mkdir ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:mkdir> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/mkdir.x64.o
    DEPENDS mkdir
    COMMENT "Copying mkdir object file"
)

# move BOF target
set(MOVE_SOURCES move/move.c)
add_library(move OBJECT ${MOVE_SOURCES})
add_custom_target(copy_move ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:move> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/move.x64.o
    DEPENDS move
    COMMENT "Copying move object file"
)

# del BOF target
set(DEL_SOURCES del/del.c)
add_library(del OBJECT ${DEL_SOURCES})
add_custom_target(copy_del ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:del> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/del.x64.o
    DEPENDS del
    COMMENT "Copying del object file"
)

# copy BOF target
set(COPY_SOURCES copy/copy.c)
add_library(copy OBJECT ${COPY_SOURCES})
add_custom_target(copy_copy ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:copy> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/copy.x64.o
    DEPENDS copy
    COMMENT "Copying copy object file"
)

# rmdir BOF target
set(RMDIR_SOURCES rmdir/rmdir.c)
add_library(rmdir OBJECT ${RMDIR_SOURCES})
add_custom_target(copy_rmdir ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:rmdir> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/rmdir.x64.o
    DEPENDS rmdir
    COMMENT "Copying rmdir object file"
)

# pwd BOF target
set(PWD_SOURCES pwd/pwd.c)
add_library(pwd OBJECT ${PWD_SOURCES})
add_custom_target(copy_pwd ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:pwd> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/pwd.x64.o
    DEPENDS pwd
    COMMENT "Copying pwd object file"
)

# cd BOF target
set(CD_SOURCES cd/cd.c)
add_library(cd OBJECT ${CD_SOURCES})
add_custom_target(copy_cd ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:cd> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/cd.x64.o
    DEPENDS cd
    COMMENT "Copying cd object file"
)
