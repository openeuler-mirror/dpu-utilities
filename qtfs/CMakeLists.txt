cmake_minimum_required(VERSION 3.0.0)

project(qtfs)

set(CMAKE_C_FLAGS "-g -O2 -fstack-protector-strong -fPIE -pie -fPIC -D_FORTIFY_SOURCE=2 -s -Wl,-z,now -Wl,-z,noexecstack")

# Build rexec and rexec_server
add_executable(rexec rexec/rexec.c rexec/rexec_sock.c)
add_executable(rexec_server rexec/rexec_server.c rexec/rexec_sock.c rexec/rexec_shim.c)
target_include_directories(rexec_server PRIVATE /usr/include/glib-2.0 /usr/lib64/glib-2.0/include)
target_link_libraries(rexec PRIVATE json-c)
target_link_libraries(rexec_server PRIVATE json-c glib-2.0)

# Build udsproxyd and libudsproxy.so
add_executable(udsproxyd ipc/uds_event.c ipc/uds_main.c)
add_library(udsproxy SHARED ipc/uds_connector.c)
target_include_directories(udsproxyd PRIVATE include/ /usr/include/glib-2.0 /usr/lib64/glib-2.0/include)
target_link_libraries(udsproxyd PRIVATE pthread glib-2.0)

# Build engine
add_executable(engine ipc/uds_main.c ipc/uds_event.c qtfs_common/user_engine.c)
target_include_directories(engine PRIVATE include/ ./ ipc/ /usr/include/glib-2.0 /usr/lib64/glib-2.0/include)
target_link_libraries(engine PRIVATE glib-2.0 pthread)
target_compile_options(engine PRIVATE "-DQTFS_SERVER")

if(DEFINED UDS_TEST_MODE OR DEFINED QTFS_TEST_MODE)
target_compile_options(engine PRIVATE "-DUDS_TEST_MODE")
target_compile_options(udsproxyd PRIVATE "-DUDS_TEST_MODE")
message(WARNING "Important risk warning: the test mode is turned on, and qtfs will expose the network port, \
                which will bring security risks and is only for testing! If you do not understand the risks,\
                please don't use or compile again without test mode macro!")
endif()

set(ignoreMe "${QTFS_TEST_MODE}${UDS_TEST_MODE}")