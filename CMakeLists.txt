cmake_minimum_required(VERSION 3.16)
project(ExtensionKit C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)

include_directories( /usr/x86_64-w64-mingw32/include )

# Main include directory at root level
set(MAIN_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/_include CACHE INTERNAL "Main include directory")

# Additional include directories for specific subprojects
set(KERBEUS_BOF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/Kerbeus-BOF/_include CACHE INTERNAL "Kerbeus-BOF include directory")
set(SQL_BOF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/SQL-BOF/common CACHE INTERNAL "SQL-BOF include directory")
set(LDAP_BOF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/LDAP-BOF/_include CACHE INTERNAL "LDAP-BOF include directory")
set(LDAP_BOF_COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/LDAP-BOF/src/common CACHE INTERNAL "LDAP-BOF common directory")
set(CREDS_BOF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Creds-BOF/_include CACHE INTERNAL "Creds-BOF include directory")

# Add global include directory
include_directories(${MAIN_INCLUDE_DIR})

# Global compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -DBOF")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -DBOF")

# Add subdirectories - all will have access to global includes and variables
add_subdirectory(AD-BOF)
add_subdirectory(Creds-BOF)
add_subdirectory(Elevation-BOF)
add_subdirectory(Execution-BOF)
add_subdirectory(Injection-BOF)
add_subdirectory(LateralMovement-BOF)
add_subdirectory(Postex-BOF)
add_subdirectory(Process-BOF)
add_subdirectory(SAL-BOF)
add_subdirectory(SAR-BOF)

# Create a single target that builds all BOF projects
add_custom_target(build-all-bofs
    DEPENDS
        ldapsearch adws_search readlaps badtakeover
        askcreds autologon credman hashdump cookie-monster get-netntlm underlaycopy
        getsystem_token uac_regshellcmd printspoofer uac_sspi DCOMPotato
        execute-assembly
        inject_cfg inject_sec inject_poolparty inject_32to64
        psexec scshell token_make token_steal winrm
        Screenshot addfirewallrule sauroneye
        findmodule findprochandle psc procfreeze
        arp cacls dir env ipconfig listdns netstat nslookup routeprint uptime useridletime whoami
        vulndrivers alwayselevated hijackablepath tokenpriv unattendfiles unquotedsvc
        smartscan nbtscan taskhound quser
    COMMENT "Building all BOF projects"
)

# Clean target for all _bin directories
add_custom_target(clean-all-bins
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/AD-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Creds-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Elevation-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Execution-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Injection-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/LateralMovement-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Postex-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/Process-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/SAL-BOF/_bin
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/SAR-BOF/_bin
    COMMENT "Cleaning all _bin directories"
)

message(STATUS "==========================================")
message(STATUS "ExtensionKit Configuration Summary")
message(STATUS "==========================================")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "CXX Compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C Standard: ${CMAKE_C_STANDARD}")
message(STATUS "CXX Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Main Include Dir: ${MAIN_INCLUDE_DIR}")
message(STATUS "==========================================")
