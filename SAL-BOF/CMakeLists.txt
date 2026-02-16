cmake_minimum_required(VERSION 3.16)
#project(SAL-BOF C)

set(CMAKE_C_STANDARD 99)

# Include directories (main _include is at root level)
include_directories(${CMAKE_SOURCE_DIR}/_include)

# Source files
set(ARP_SOURCES arp/arp.c)
set(CACLS_SOURCES cacls/cacls.c)
set(DIR_SOURCES dir/dir.c)
set(ENV_SOURCES env/env.c)
set(IPCONFIG_SOURCES ipconfig/ipconfig.c)
set(LISTDNS_SOURCES listdns/listdns.c)
set(NETSTAT_SOURCES netstat/netstat.c)
set(NSLOOKUP_SOURCES nslookup/nslookup.c)
set(ROUTEPRINT_SOURCES routeprint/routeprint.c)
set(UPTIME_SOURCES uptime/uptime.c)
set(USERIDLETIME_SOURCES useridletime/useridletime.c)
set(WHOAMI_SOURCES whoami/whoami.c)
set(VULNDRIVERS_SOURCES privcheck/vulnerabledrivers.c)
set(ALWAYSELEVATED_SOURCES privcheck/alwaysinstallelevated.c)
set(HIJACKABLEPATH_SOURCES privcheck/hijackablepath.c)
set(TOKENPRIV_SOURCES privcheck/tokenprivileges.c)
set(UNATTENDFILES_SOURCES privcheck/unattendfiles.c)
set(UNQUOTEDSVC_SOURCES privcheck/unquotedsvcpath.c)
set(AUTOLOGON_SOURCES privcheck/autologon.c)
set(CREDMANAGER_SOURCES privcheck/credentialmanager.c)
set(MODAUTORUN_SOURCES privcheck/modifiableautorun.c)
set(MODSVC_SOURCES privcheck/modifiablesvc.c)
set(PSHISTORY_SOURCES privcheck/pshistory.c)
set(UACSTATUS_SOURCES privcheck/uacstatus.c)
set(PRIVCHECK_ALL_SOURCES privcheck/privcheck_all.c)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -DBOF")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")

# Object file targets
add_library(arp OBJECT ${ARP_SOURCES})
add_library(cacls OBJECT ${CACLS_SOURCES})
add_library(dir OBJECT ${DIR_SOURCES})
add_library(env OBJECT ${ENV_SOURCES})
add_library(ipconfig OBJECT ${IPCONFIG_SOURCES})
add_library(listdns OBJECT ${LISTDNS_SOURCES})
add_library(netstat OBJECT ${NETSTAT_SOURCES})

add_library(nslookup OBJECT ${NSLOOKUP_SOURCES})
target_compile_options(nslookup PRIVATE -fno-jump-tables)

add_library(routeprint OBJECT ${ROUTEPRINT_SOURCES})
add_library(uptime OBJECT ${UPTIME_SOURCES})
add_library(useridletime OBJECT ${USERIDLETIME_SOURCES})
add_library(whoami OBJECT ${WHOAMI_SOURCES})

# Privcheck targets
add_library(vulndrivers OBJECT ${VULNDRIVERS_SOURCES})
target_compile_options(vulndrivers PRIVATE -w -Wno-incompatible-pointer-types)

add_library(alwayselevated OBJECT ${ALWAYSELEVATED_SOURCES})
target_compile_options(alwayselevated PRIVATE -w -Wno-incompatible-pointer-types)

add_library(hijackablepath OBJECT ${HIJACKABLEPATH_SOURCES})
target_compile_options(hijackablepath PRIVATE -w -Wno-incompatible-pointer-types)

add_library(tokenpriv OBJECT ${TOKENPRIV_SOURCES})
target_compile_options(tokenpriv PRIVATE -w -Wno-incompatible-pointer-types)

add_library(unattendfiles OBJECT ${UNATTENDFILES_SOURCES})
target_compile_options(unattendfiles PRIVATE -w -Wno-incompatible-pointer-types)

add_library(unquotedsvc OBJECT ${UNQUOTEDSVC_SOURCES})
target_compile_options(unquotedsvc PRIVATE -w -Wno-incompatible-pointer-types)

add_library(autologon OBJECT ${AUTOLOGON_SOURCES})
target_compile_options(autologon PRIVATE -w -Wno-incompatible-pointer-types)

add_library(credmanager OBJECT ${CREDMANAGER_SOURCES})
target_compile_options(credmanager PRIVATE -w -Wno-incompatible-pointer-types)

add_library(modautorun OBJECT ${MODAUTORUN_SOURCES})
target_compile_options(modautorun PRIVATE -w -Wno-incompatible-pointer-types)

add_library(modsvc OBJECT ${MODSVC_SOURCES})
target_compile_options(modsvc PRIVATE -w -Wno-incompatible-pointer-types)

add_library(pshistory OBJECT ${PSHISTORY_SOURCES})
target_compile_options(pshistory PRIVATE -w -Wno-incompatible-pointer-types)

add_library(uacstatus OBJECT ${UACSTATUS_SOURCES})
target_compile_options(uacstatus PRIVATE -w -Wno-incompatible-pointer-types)

add_library(privcheck_all OBJECT ${PRIVCHECK_ALL_SOURCES})
target_compile_options(privcheck_all PRIVATE -w -Wno-incompatible-pointer-types)

# Custom command to download vulnerable driver list
add_custom_target(download_vulnerable_driver_list
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/privcheck/download_vulnerable_driver_list.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Downloading vulnerable driver list"
)

add_dependencies(vulndrivers download_vulnerable_driver_list)

# Create _bin directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/_bin)

# Custom commands to copy object files to _bin
add_custom_target(copy_arp ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:arp> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/arp.x64.o
    DEPENDS arp
    COMMENT "Copying arp object file"
)

add_custom_target(copy_cacls ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:cacls> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/cacls.x64.o
    DEPENDS cacls
    COMMENT "Copying cacls object file"
)

add_custom_target(copy_dir ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:dir> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/dir.x64.o
    DEPENDS dir
    COMMENT "Copying dir object file"
)

add_custom_target(copy_env ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:env> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/env.x64.o
    DEPENDS env
    COMMENT "Copying env object file"
)

add_custom_target(copy_ipconfig ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:ipconfig> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/ipconfig.x64.o
    DEPENDS ipconfig
    COMMENT "Copying ipconfig object file"
)

add_custom_target(copy_listdns ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:listdns> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/listdns.x64.o
    DEPENDS listdns
    COMMENT "Copying listdns object file"
)

add_custom_target(copy_netstat ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:netstat> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/netstat.x64.o
    DEPENDS netstat
    COMMENT "Copying netstat object file"
)

add_custom_target(copy_nslookup ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:nslookup> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/nslookup.x64.o
    DEPENDS nslookup
    COMMENT "Copying nslookup object file"
)

add_custom_target(copy_routeprint ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:routeprint> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/routeprint.x64.o
    DEPENDS routeprint
    COMMENT "Copying routeprint object file"
)

add_custom_target(copy_uptime ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:uptime> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/uptime.x64.o
    DEPENDS uptime
    COMMENT "Copying uptime object file"
)

add_custom_target(copy_useridletime ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:useridletime> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/useridletime.x64.o
    DEPENDS useridletime
    COMMENT "Copying useridletime object file"
)

add_custom_target(copy_whoami ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:whoami> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/whoami.x64.o
    DEPENDS whoami
    COMMENT "Copying whoami object file"
)

add_custom_target(copy_vulndrivers ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:vulndrivers> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/vulndrivers.x64.o
    DEPENDS vulndrivers
    COMMENT "Copying vulndrivers object file"
)

add_custom_target(copy_alwayselevated ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:alwayselevated> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/alwayselevated.x64.o
    DEPENDS alwayselevated
    COMMENT "Copying alwayselevated object file"
)

add_custom_target(copy_hijackablepath ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:hijackablepath> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/hijackablepath.x64.o
    DEPENDS hijackablepath
    COMMENT "Copying hijackablepath object file"
)

add_custom_target(copy_tokenpriv ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:tokenpriv> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/tokenpriv.x64.o
    DEPENDS tokenpriv
    COMMENT "Copying tokenpriv object file"
)

add_custom_target(copy_unattendfiles ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:unattendfiles> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/unattendfiles.x64.o
    DEPENDS unattendfiles
    COMMENT "Copying unattendfiles object file"
)

add_custom_target(copy_unquotedsvc ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:unquotedsvc> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/unquotedsvc.x64.o
    DEPENDS unquotedsvc
    COMMENT "Copying unquotedsvc object file"
)

add_custom_target(copy_autologon ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:autologon> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/autologon.x64.o
    DEPENDS autologon
    COMMENT "Copying autologon object file"
)

add_custom_target(copy_credmanager ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:credmanager> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/credmanager.x64.o
    DEPENDS credmanager
    COMMENT "Copying credmanager object file"
)

add_custom_target(copy_modautorun ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:modautorun> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/modautorun.x64.o
    DEPENDS modautorun
    COMMENT "Copying modautorun object file"
)

add_custom_target(copy_modsvc ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:modsvc> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/modsvc.x64.o
    DEPENDS modsvc
    COMMENT "Copying modsvc object file"
)

add_custom_target(copy_pshistory ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:pshistory> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/pshistory.x64.o
    DEPENDS pshistory
    COMMENT "Copying pshistory object file"
)

add_custom_target(copy_uacstatus ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:uacstatus> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/uacstatus.x64.o
    DEPENDS uacstatus
    COMMENT "Copying uacstatus object file"
)

add_custom_target(copy_privcheck_all ALL
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_OBJECTS:privcheck_all> ${CMAKE_CURRENT_SOURCE_DIR}/_bin/privcheck_all.x64.o
    DEPENDS privcheck_all
    COMMENT "Copying privcheck_all object file"
)
