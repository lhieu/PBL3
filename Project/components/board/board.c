#include "board_esp32c3_devkitc.h"
#include <driver/gpio.h>


void board_init(void)
{
    // Cấu hình các GPIO LED
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << LIGHT_GPIO_RED) |
                        (1ULL << LIGHT_GPIO_GREEN) |
                        (1ULL << LIGHT_GPIO_BLUE) |
                        (1ULL << LIGHT_GPIO_COLD) |
                        (1ULL << LIGHT_GPIO_WARM),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&io_conf);

    // Cấu hình GPIO nút nhấn nếu muốn
    gpio_config_t btn_conf = {
        .pin_bit_mask = (1ULL << LIGHT_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = (LIGHT_BUTTON_ACTIVE_LEVEL == 0) ? 1 : 0,
        .pull_down_en = (LIGHT_BUTTON_ACTIVE_LEVEL == 1) ? 1 : 0,
        .intr_type = GPIO_INTR_DISABLE
    };
    gpio_config(&btn_conf);
}
