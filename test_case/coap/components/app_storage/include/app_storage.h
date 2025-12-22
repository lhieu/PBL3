#pragma once

#include "esp_err.h"
#include "nvs_flash.h"

#ifdef __cplusplus
extern "C" {
#endif

// Hàm khởi tạo NVS (Non-Volatile Storage)
esp_err_t app_storage_init(void);

#ifdef __cplusplus
}
#endif
