cmake_minimum_required(VERSION 3.5)

add_compile_options(-fdiagnostics-color=always)

# Đường dẫn RainMaker
set(ENV{RAIMAKER_PATH} "${CMAKE_CURRENT_LIST_DIR}/../esp-rainmaker-master")
if(NOT DEFINED ENV{RAIMAKER_PATH})
    message(FATAL_ERROR "Please set RAIMAKER_PATH to esp-rainmaker repo")
endif()

# Thêm component riêng của project
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/../components/light_driver
    ${CMAKE_CURRENT_LIST_DIR}/../components/button
    ${CMAKE_CURRENT_LIST_DIR}/../components/app_storage
   # ${CMAKE_CURRENT_LIST_DIR}/../components/qrcode
    ${CMAKE_CURRENT_LIST_DIR}/../components/app_wifi
    $ENV{RAIMAKER_PATH}/components/esp_rainmaker
    $ENV{RAIMAKER_PATH}/components/esp_schedule
    $ENV{RAIMAKER_PATH}/components/rmaker_common
)

# Loại bỏ các component không dùng
set(EXCLUDE_COMPONENTS "coap" "asio" "espressif__network_provisioning")

# Include project
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
set(PROJECT_VER "3.5.2")
project(6_performance_optimize)
