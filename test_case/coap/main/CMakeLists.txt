idf_component_register(
    SRCS "app_main.c" "app_driver.c"
    INCLUDE_DIRS "."
    REQUIRES esp_wifi esp_event esp_netif nvs_flash iot_button light_driver libcoap app_storage
)
