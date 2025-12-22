#pragma once
#include <stdbool.h>   // cho kiểu bool

// Các cấu trúc và khai báo khác
typedef struct {
    int gpio_red;
    int gpio_green;
    int gpio_blue;
    int gpio_cold;
    int gpio_warm;
    int fade_period_ms;
    int blink_period_ms;
    int freq_hz;
    int clk_cfg;
    int duty_resolution;
} light_driver_config_t;

// Hàm khởi tạo driver
void light_driver_init(void);

// Hàm bật/tắt đèn
void light_driver_set_switch(bool on);
