#pragma once

#include <stdbool.h>  // Cho kiểu bool
#include "esp32c3_devboard.h"

// GPIO và thông số LED / nút nhấn

#define LIGHT_GPIO_RED            18
#define LIGHT_GPIO_GREEN          19
#define LIGHT_GPIO_BLUE           21
#define LIGHT_GPIO_COLD           22
#define LIGHT_GPIO_WARM           23
#define LIGHT_FADE_PERIOD_MS      1000
#define LIGHT_BLINK_PERIOD_MS     500
#define LIGHT_FREQ_HZ             5000

// Prototype cho hàm app_driver_set_state

