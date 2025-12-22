#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Button */
#define LIGHT_BUTTON_GPIO         0       // GPIO gắn nút nhấn
#define LIGHT_BUTTON_ACTIVE_LEVEL 0       // 0 = active low, 1 = active high

/* LED GPIOs */
#define LIGHT_GPIO_RED    2
#define LIGHT_GPIO_GREEN  3
#define LIGHT_GPIO_BLUE   4
#define LIGHT_GPIO_COLD   5
#define LIGHT_GPIO_WARM   6

/* Light driver timing */
#define LIGHT_FADE_PERIOD_MS  10
#define LIGHT_BLINK_PERIOD_MS 500
#define LIGHT_FREQ_HZ         5000

#ifdef __cplusplus
}
#endif
