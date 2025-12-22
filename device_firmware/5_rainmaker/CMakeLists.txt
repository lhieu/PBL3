# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

add_compile_options(-fdiagnostics-color=always)
set(ENV{RAIMAKER_PATH} "${CMAKE_CURRENT_LIST_DIR}/../esp-rainmaker-master")
# Determine whether to define RAIMAKER_PATH
if(NOT DEFINED ENV{RAIMAKER_PATH})
    message(FATAL_ERROR "Please set RAIMAKER_PATH to esp-rainmaker repo")
endif(NOT DEFINED ENV{RAIMAKER_PATH})

# Add RainMaker components and other common application components
set(EXTRA_COMPONENT_DIRS ${CMAKE_CURRENT_LIST_DIR}/../components/light_driver
                        ${CMAKE_CURRENT_LIST_DIR}/../components/button
                        ${CMAKE_CURRENT_LIST_DIR}/../components/app_storage
                        ${CMAKE_CURRENT_LIST_DIR}/../components/app_wifi
                       # ${CMAKE_CURRENT_LIST_DIR}/../components/qrcode
                        $ENV{RAIMAKER_PATH}/components/esp_rainmaker
                        $ENV{RAIMAKER_PATH}/components/esp_schedule
                        
                        $ENV{RAIMAKER_PATH}/components/rmaker_common
                        )
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Alias network_provisioning to the built-in wifi_provisioning in ESP-IDF 5.5+
idf_build_get_property(idf_components BUILD_COMPONENTS)
if(NOT TARGET espressif__network_provisioning AND TARGET wifi_provisioning)
    add_library(espressif__network_provisioning INTERFACE)
    target_link_libraries(espressif__network_provisioning INTERFACE wifi_provisioning)
    message(STATUS "Aliased espressif__network_provisioning -> wifi_provisioning")
endif()
set(PROJECT_VER "3.5.6")
project(5_rainmaker)
