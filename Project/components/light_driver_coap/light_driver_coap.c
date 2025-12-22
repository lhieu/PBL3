#include "light_driver_coap.h"
#include "driver/ledc.h"
#include "esp_log.h"
#include "driver/gpio.h"

static const char *TAG = "light_driver_coap";
static bool s_light_state = false;

esp_err_t light_driver_coap_init(const light_driver_config_t *config)
{
    ledc_timer_config_t ledc_timer = {
        .speed_mode      = LEDC_LOW_SPEED_MODE,
        .timer_num       = LEDC_TIMER_0,
        .duty_resolution = config->duty_resolution,
        .freq_hz         = config->freq_hz,
        .clk_cfg         = config->clk_cfg
    };
    ledc_timer_config(&ledc_timer);

    // TODO: cấu hình các kênh LED Red/Green/Blue/Warm/Cold nếu cần
    ESP_LOGI(TAG, "Light driver for COAP project initialized");

    return ESP_OK;
}

void light_driver_set_switch(bool on)
{
    s_light_state = on;
    // TODO: bật/tắt LED theo s_light_state
    ESP_LOGI(TAG, "Light %s", on ? "ON" : "OFF");
}
