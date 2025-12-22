#pragma once

#include "driver/gpio.h"
#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Loại nút (hiện tại chỉ hỗ trợ GPIO)
typedef enum {
    BUTTON_TYPE_GPIO = 0,
} button_type_t;

// Cấu hình cho nút GPIO
typedef struct {
    gpio_num_t gpio_num;       // Chân GPIO
    uint32_t active_level;     // Mức kích hoạt (0 hoặc 1)
} gpio_button_config_t;

// Cấu hình tổng quát cho nút
typedef struct {
    button_type_t type;
    gpio_button_config_t gpio_button_config;
} button_config_t;

// Định nghĩa kiểu handle cho button
typedef void* button_handle_t;

// Kiểu hàm callback
typedef void (*button_callback_t)(void *arg);

// Hàm khởi tạo nút nhấn
esp_err_t iot_button_coap_init(int gpio_num);

// Đăng ký callback
void iot_button_coap_set_callback(button_callback_t cb, void *arg);

// Kiểm tra nút có đang nhấn không
bool iot_button_coap_is_pressed(void);

#ifdef __cplusplus
}
#endif
