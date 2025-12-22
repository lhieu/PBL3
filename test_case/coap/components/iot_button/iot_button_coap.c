#include "iot_button.h"
#include "driver/gpio.h"

static int button_gpio = -1;
static button_callback_t button_cb = NULL;
static void *callback_arg = NULL;

esp_err_t iot_button_coap_init(int gpio_num)
{
    button_gpio = gpio_num;
    gpio_config_t io_conf = {
        .pin_bit_mask = 1ULL << button_gpio,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE
    };
    return gpio_config(&io_conf);
}

void iot_button_coap_set_callback(button_callback_t cb, void *arg)
{
    button_cb = cb;
    callback_arg = arg;
    // (Có thể thêm logic quét nút và gọi callback khi nhấn)
}

bool iot_button_coap_is_pressed(void)
{
    if (button_gpio < 0) return false;
    return gpio_get_level(button_gpio) == 0;  // nếu active thấp
}
