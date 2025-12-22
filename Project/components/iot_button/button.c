#include "iot_button.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_log.h"


button_handle_t iot_button_create(button_config_t *config) {
    // khởi tạo button theo config
    return (button_handle_t)config; // ví dụ đơn giản
}

esp_err_t iot_button_register_cb(button_handle_t btn_handle, button_event_t event, void (*callback)(void)) {
    // đăng ký callback
    return ESP_OK;
}
