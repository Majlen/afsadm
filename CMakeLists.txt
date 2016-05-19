cmake_minimum_required (VERSION 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
project (afsadm)
find_package(Readline REQUIRED)
find_package(KRB5 REQUIRED)

include_directories(${Readline_INCLUDE_DIR})
include_directories(${KRB5_INCLUDE_DIRS})

add_executable(afsadmd parseconf.c server.c struct.c afsadmd.c)
add_executable(afsadm afsadmclnt.c)
add_library(kafs SHARED afssys.c)

set_target_properties(kafs PROPERTIES COMPILE_FLAGS -DAFS_SYSCALL=65)
target_link_libraries(afsadmd krb5 com_err k5crypto kafs)
target_link_libraries(afsadm krb5 com_err k5crypto ${Readline_LIBRARY})
add_dependencies(afsadmd kafs)
