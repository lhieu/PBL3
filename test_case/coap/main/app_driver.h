#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "esp_err.h"
#include <stdbool.h>

/**
 * @brief Khởi tạo các phần cứng trong hệ thống
 */
esp_err_t app_driver_init(void);

/**
 * @brief Đặt trạng thái của thiết bị (bật/tắt đèn, relay,...)
 */
int IRAM_ATTR app_driver_set_state(bool state);

/**
 * @brief Lấy trạng thái hiện tại của thiết bị
 */
bool app_driver_get_state(void);

#ifdef __cplusplus
}
#endif
