#ifndef _IOT_BUTTON_H_
#define _IOT_BUTTON_H_

#include "esp_err.h"
#include "driver/gpio.h"
#include <stdbool.h>

// Các kiểu dữ liệu
typedef enum {
    BUTTON_TYPE_GPIO,
} button_type_t;

typedef struct {
    button_type_t type;
    struct {
        gpio_num_t gpio_num;
        int active_level; // 0 = active low, 1 = active high
    } gpio_button_config;
} button_config_t;

typedef void* button_handle_t;

typedef enum {
    BUTTON_PRESS_DOWN,
    BUTTON_PRESS_UP,
    BUTTON_LONG_PRESS,
} button_event_t;

// Hàm
button_handle_t iot_button_create(button_config_t *config);
esp_err_t iot_button_register_cb(button_handle_t btn_handle, button_event_t event, void (*callback)(void));

#endif // _IOT_BUTTON_H_
