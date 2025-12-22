#include "light_driver.h"
#include "driver/gpio.h"
#include "esp_log.h"

static const char *TAG = "light_driver";

// cấu hình driver
static light_driver_config_t s_driver_config;

void light_driver_init(void)
{
    ESP_LOGI(TAG, "Light driver initialized");

    // Khởi tạo GPIO (ví dụ)
    gpio_reset_pin(s_driver_config.gpio_red);
    gpio_set_direction(s_driver_config.gpio_red, GPIO_MODE_OUTPUT);

    // các GPIO khác tương tự...
}

// Bật/tắt đèn
void light_driver_set_switch(bool on)
{
    gpio_set_level(s_driver_config.gpio_red, on ? 1 : 0);
    gpio_set_level(s_driver_config.gpio_green, on ? 1 : 0);
    gpio_set_level(s_driver_config.gpio_blue, on ? 1 : 0);
}
