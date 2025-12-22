#ifndef _APP_DRIVER_H_
#define _APP_DRIVER_H_

#include <stdbool.h>
#include "esp_err.h"

// Khai báo các hàm của app_driver.c
void app_driver_init(void);
int IRAM_ATTR app_driver_set_state(bool state);
bool app_driver_get_state(void);

#endif // _APP_DRIVER_H_
