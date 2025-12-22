/*
  app_driver.c
  Thin wrapper: button -> app state -> light driver
*/

#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "iot_button_coap.h"      // your button component header (names you provided)
#include "light_driver_coap.h"    // your light driver component header
#include "esp32c3_devboard.h"     // board pin definitions (LIGHT_BUTTON_GPIO, etc.)
#include "app_driver.h"           // header you should have with prototypes

static const char *TAG = "app_driver";

static bool s_output_state = true;

/* push button callback from iot_button component */
static void push_btn_cb(void *arg)
{
    (void)arg;
    bool new_state = !s_output_state;
    app_driver_set_state(new_state);
}

/* Initialize app driver: button + light */
esp_err_t app_driver_init(void)
{
    esp_err_t err = ESP_OK;

    /* init button component on configured pin */
    if (iot_button_coap_init(LIGHT_BUTTON_GPIO) != ESP_OK) {
        ESP_LOGW(TAG, "iot_button_coap_init failed (but continuing)");
    } else {
        /* register callback */
        iot_button_coap_set_callback(push_btn_cb, NULL);
    }

    /* configure light driver */
    light_driver_config_t cfg = {
        .gpio_red = LIGHT_GPIO_RED,
        .gpio_green = LIGHT_GPIO_GREEN,
        .gpio_blue = LIGHT_GPIO_BLUE,
        .gpio_cold = LIGHT_GPIO_COLD,
        .gpio_warm = LIGHT_GPIO_WARM,
        .fade_period_ms = LIGHT_FADE_PERIOD_MS,
        .blink_period_ms = LIGHT_BLINK_PERIOD_MS,
        .freq_hz = LIGHT_FREQ_HZ,
        /* other fields depend on your implementation; only set what exists */
    };

    if (light_driver_coap_init(&cfg) != ESP_OK) {
        ESP_LOGW(TAG, "light_driver_coap_init failed");
        err = ESP_FAIL;
    }

    /* default to ON */
    s_output_state = true;
    light_driver_set_switch(true);

    return err;
}

/* set on/off (called from button callback or other code) */
esp_err_t app_driver_set_state(bool state)
{
    if (s_output_state == state) {
        return ESP_OK;
    }
    s_output_state = state;
    if (s_output_state) {
        ESP_LOGI(TAG, "Light ON");
        light_driver_set_switch(true);
    } else {
        ESP_LOGI(TAG, "Light OFF");
        light_driver_set_switch(false);
    }
    return ESP_OK;
}

bool app_driver_get_state(void)
{
    return s_output_state;
}
