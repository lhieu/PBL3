# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

add_compile_options(-fdiagnostics-color=always)

# Add common application components
set(EXTRA_COMPONENT_DIRS 
    "C:/book-esp32c3-iot-projects-main/test_case/coap/components/light_driver"
    "C:/book-esp32c3-iot-projects-main/test_case/coap/components/iot_button"
    "C:/book-esp32c3-iot-projects-main/test_case/coap/components/app_storage"
    "C:/book-esp32c3-iot-projects-main/test_case/coap/components/libcoap"
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(coap)
