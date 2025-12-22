cmake_minimum_required(VERSION 3.16)

add_compile_options(-fdiagnostics-color=always)

# Add common application components
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../../Project/components/board
    ${CMAKE_CURRENT_LIST_DIR}/../../Project/components/light_driver
    ${CMAKE_CURRENT_LIST_DIR}/../../Project/components/iot_button
    ${CMAKE_CURRENT_LIST_DIR}/../../Project/components/app_storage
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tcp_socket)
