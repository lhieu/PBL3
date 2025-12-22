#pragma once

#include "esp_err.h"
#include "driver/ledc.h"

typedef struct {
    int gpio_red;
    int gpio_green;
    int gpio_blue;
    int gpio_cold;
    int gpio_warm;
    int fade_period_ms;
    int blink_period_ms;
    int freq_hz;
    ledc_clk_cfg_t clk_cfg;
    ledc_timer_bit_t duty_resolution;
} light_driver_config_t;

esp_err_t light_driver_coap_init(const light_driver_config_t *config);
void light_driver_set_switch(bool on);
