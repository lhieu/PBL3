// Copyright 2017 Espressif Systems
// Licensed under the Apache License, Version 2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "esp_log.h"
#include "driver/ledc.h"
#include "soc/ledc_reg.h"
#include "soc/ledc_struct.h"
#include "esp_timer.h"
#include "iot_led.h"
#include "esp_attr.h"

void gamma_table_create(uint16_t *table, uint8_t correction)
{
    for (int i = 0; i < GAMMA_TABLE_SIZE; i++) {
        float normalized = (float)i / (GAMMA_TABLE_SIZE - 1);
        table[i] = (uint16_t)(pow(normalized, correction) * UINT16_MAX);
    }
}


#define LEDC_FADE_MARGIN (10)
#define LEDC_TIMER_PRECISION (LEDC_TIMER_13_BIT)
#define LEDC_VALUE_TO_DUTY(value) (value * ((1 << LEDC_TIMER_PRECISION)) / (UINT16_MAX))
#define LEDC_FIXED_Q (8)
#define FLOATINT_2_FIXED(X, Q) ((int)((X)*(0x1U << Q)))
#define FIXED_2_FLOATING(X, Q) ((int)((X)/(0x1U << Q)))
#define GET_FIXED_INTEGER_PART(X, Q) (X >> Q)
#define GET_FIXED_DECIMAL_PART(X, Q) (X & ((0x1U << Q) - 1))

typedef struct {
    int cur;
    int final;
    int step;
    int cycle;
    size_t num;
} ledc_fade_data_t;

typedef struct {
    ledc_fade_data_t fade_data[LEDC_CHANNEL_MAX];
    ledc_mode_t speed_mode;
    ledc_timer_t timer_num;
    int timer_id;
} iot_light_t;

static const char *TAG = "iot_light";
static DRAM_ATTR iot_light_t *g_light_config = NULL;
static DRAM_ATTR uint16_t *g_gamma_table = NULL;
static DRAM_ATTR bool g_hw_timer_started = false;
static esp_timer_handle_t g_fade_esp_timer = NULL;

// Forward declarations
static IRAM_ATTR void fade_timercb(void *para);

static void IRAM_ATTR esp_fade_timer_cb(void* arg) {
    fade_timercb(arg);
}

static void iot_timer_create(int timer_id, uint32_t timer_interval_ms) {
    if (g_fade_esp_timer != NULL) return;

    const esp_timer_create_args_t create_args = {
        .callback = &esp_fade_timer_cb,
        .arg = (void*)(intptr_t)timer_id,
        .name = "fade_timer"
    };
    esp_timer_create(&create_args, &g_fade_esp_timer);
}

static void iot_timer_start(void) {
    if (g_fade_esp_timer == NULL) return;

    uint64_t period_us = (uint64_t)DUTY_SET_CYCLE * 1000ULL;
    if (esp_timer_start_periodic(g_fade_esp_timer, period_us) == ESP_OK) {
        g_hw_timer_started = true;
    } else {
        ESP_LOGE(TAG, "esp_timer_start_periodic failed");
    }
}

static void iot_timer_stop(void) {
    if (g_fade_esp_timer == NULL) return;

    if (esp_timer_stop(g_fade_esp_timer) == ESP_OK) {
        g_hw_timer_started = false;
    } else {
        ESP_LOGE(TAG, "esp_timer_stop failed");
    }
}

// Duty/fade helpers
static IRAM_ATTR esp_err_t iot_ledc_duty_config(ledc_mode_t speed_mode, ledc_channel_t channel, int hpoint_val, int duty_val,
        uint32_t duty_direction, uint32_t duty_num, uint32_t duty_cycle, uint32_t duty_scale)
{
    if (hpoint_val >= 0) {
        LEDC.channel_group[speed_mode].channel[channel].hpoint.hpoint = hpoint_val & LEDC_HPOINT_LSCH1_V;
    }

    if (duty_val >= 0) {
        LEDC.channel_group[speed_mode].channel[channel].duty.duty = duty_val;
    }

    LEDC.channel_group[speed_mode].channel[channel].conf1.val =
        ((duty_direction & LEDC_DUTY_INC_LSCH0_V) << LEDC_DUTY_INC_LSCH0_S) |
        ((duty_num & LEDC_DUTY_NUM_LSCH0_V) << LEDC_DUTY_NUM_LSCH0_S) |
        ((duty_cycle & LEDC_DUTY_CYCLE_LSCH0_V) << LEDC_DUTY_CYCLE_LSCH0_S) |
        ((duty_scale & LEDC_DUTY_SCALE_LSCH0_V) << LEDC_DUTY_SCALE_LSCH0_S);

    LEDC.channel_group[speed_mode].channel[channel].conf0.sig_out_en = 1;
    LEDC.channel_group[speed_mode].channel[channel].conf1.duty_start = 1;
    if (speed_mode == LEDC_LOW_SPEED_MODE) {
        LEDC.channel_group[speed_mode].channel[channel].conf0.low_speed_update = 1;
    }

    return ESP_OK;
}

static IRAM_ATTR esp_err_t _iot_set_fade_with_step(ledc_mode_t speed_mode, ledc_channel_t channel, uint32_t target_duty, int scale, int cycle_num) {
    uint32_t duty_cur = LEDC.channel_group[speed_mode].channel[channel].duty_rd.duty_read >> 4;
    int step_num = 0;
    int dir = LEDC_DUTY_DIR_DECREASE;

    if (scale > 0) {
        if (duty_cur > target_duty) {
            step_num = (duty_cur - target_duty) / scale;
            step_num = step_num > 1023 ? 1023 : step_num;
            scale = (step_num == 1023) ? (duty_cur - target_duty) / step_num : scale;
        } else {
            dir = LEDC_DUTY_DIR_INCREASE;
            step_num = (target_duty - duty_cur) / scale;
            step_num = step_num > 1023 ? 1023 : step_num;
            scale = (step_num == 1023) ? (target_duty - duty_cur) / step_num : scale;
        }
    }

    if (scale > 0 && step_num > 0) {
        iot_ledc_duty_config(speed_mode, channel, -1, duty_cur << 4, dir, step_num, cycle_num, scale);
    } else {
        iot_ledc_duty_config(speed_mode, channel, -1, target_duty << 4, dir, 0, 1, 0);
    }
    return ESP_OK;
}

static IRAM_ATTR esp_err_t _iot_set_fade_with_time(ledc_mode_t speed_mode, ledc_channel_t channel, uint32_t target_duty, int max_fade_time_ms)
{
    uint32_t duty_cur = LEDC.channel_group[speed_mode].channel[channel].duty_rd.duty_read >> 4;
    uint32_t duty_delta = target_duty > duty_cur ? target_duty - duty_cur : duty_cur - target_duty;

    if (duty_delta == 0) {
        return _iot_set_fade_with_step(speed_mode, channel, target_duty, 0, 0);
    }

    int total_cycles = max_fade_time_ms * 100 / DUTY_SET_CYCLE; // rough freq approximation
    if (total_cycles == 0) {
        return _iot_set_fade_with_step(speed_mode, channel, target_duty, 0, 0);
    }

    int scale, cycle_num;
    if (total_cycles > duty_delta) {
        scale = 1;
        cycle_num = total_cycles / duty_delta;
        if (cycle_num > LEDC_DUTY_NUM_LSCH0_V) cycle_num = LEDC_DUTY_NUM_LSCH0_V;
    } else {
        scale = duty_delta / total_cycles;
        if (scale > LEDC_DUTY_SCALE_LSCH0_V) scale = LEDC_DUTY_SCALE_LSCH0_V;
        cycle_num = 1;
    }

    return _iot_set_fade_with_step(speed_mode, channel, target_duty, scale, cycle_num);
}

static IRAM_ATTR esp_err_t _iot_update_duty(ledc_mode_t speed_mode, ledc_channel_t channel)
{
    LEDC.channel_group[speed_mode].channel[channel].conf0.sig_out_en = 1;
    LEDC.channel_group[speed_mode].channel[channel].conf1.duty_start = 1;
    if (speed_mode == LEDC_LOW_SPEED_MODE) {
        LEDC.channel_group[speed_mode].channel[channel].conf0.low_speed_update = 1;
    }
    return ESP_OK;
}

static IRAM_ATTR uint32_t gamma_value_to_duty(int value)
{
    uint32_t tmp_q = GET_FIXED_INTEGER_PART(value, LEDC_FIXED_Q);
    uint32_t tmp_r = GET_FIXED_DECIMAL_PART(value, LEDC_FIXED_Q);

    uint16_t cur = LEDC_VALUE_TO_DUTY(g_gamma_table[tmp_q]);
    uint16_t next = tmp_q < (GAMMA_TABLE_SIZE - 1) ? LEDC_VALUE_TO_DUTY(g_gamma_table[tmp_q + 1]) : cur;
    uint32_t tmp = (cur + (next - cur) * tmp_r / (0x1U << LEDC_FIXED_Q));
    return tmp;
}

static IRAM_ATTR void fade_timercb(void *para)
{
    (void)para;
    int idle_channel_num = 0;

    for (int channel = 0; channel < LEDC_CHANNEL_MAX; channel++) {
        ledc_fade_data_t *fade_data = g_light_config->fade_data + channel;

        if (fade_data->num > 0) {
            fade_data->num--;
            if (fade_data->step) {
                fade_data->cur += fade_data->step;
                if (fade_data->num != 0) {
                    _iot_set_fade_with_time(g_light_config->speed_mode, channel,
                                            gamma_value_to_duty(fade_data->cur),
                                            DUTY_SET_CYCLE - LEDC_FADE_MARGIN);
                } else {
                    iot_ledc_duty_config(g_light_config->speed_mode, channel,
                                         -1, gamma_value_to_duty(fade_data->cur) << 4,
                                         1, 1, 1, 0);
                }
                _iot_update_duty(g_light_config->speed_mode, channel);
            } else {
                iot_ledc_duty_config(g_light_config->speed_mode, channel,
                                     -1, gamma_value_to_duty(fade_data->cur) << 4,
                                     1, 1, 1, 0);
                _iot_update_duty(g_light_config->speed_mode, channel);
            }
        } else if (fade_data->cycle) {
            fade_data->num = fade_data->cycle - 1;
            if (fade_data->step) fade_data->step *= -1;
            _iot_set_fade_with_time(g_light_config->speed_mode, channel,
                                    gamma_value_to_duty(fade_data->cur),
                                    DUTY_SET_CYCLE - LEDC_FADE_MARGIN);
            _iot_update_duty(g_light_config->speed_mode, channel);
        } else {
            idle_channel_num++;
        }
    }

    if (idle_channel_num >= LEDC_CHANNEL_MAX) {
        iot_timer_stop();
    }
}

// ----------------- PUBLIC API -----------------
esp_err_t iot_led_regist_channel(ledc_channel_t channel, gpio_num_t gpio_num)
{
    if (!g_light_config) return ESP_FAIL;

    ledc_channel_config_t ledc_ch = {
        .gpio_num   = gpio_num,
        .speed_mode = g_light_config->speed_mode,
        .channel    = channel,
        .intr_type  = LEDC_INTR_DISABLE,
        .timer_sel  = g_light_config->timer_num,
        .duty       = 0,
        .hpoint     = 0
    };

    esp_err_t ret = ledc_channel_config(&ledc_ch);
    if (ret != ESP_OK) {
        ESP_LOGE("iot_led", "Failed to config channel %d GPIO %d", channel, gpio_num);
        return ret;
    }

    // Khởi tạo fade_data
    g_light_config->fade_data[channel].cur = 0;
    g_light_config->fade_data[channel].final = 0;
    g_light_config->fade_data[channel].step = 0;
    g_light_config->fade_data[channel].cycle = 0;
    g_light_config->fade_data[channel].num = 0;

    ESP_LOGI("iot_led", "Registered LEDC channel %d at GPIO %d", channel, gpio_num);
    return ESP_OK;
}


esp_err_t iot_led_set_channel(ledc_channel_t channel, uint8_t value, uint32_t fade_ms)
{
    if (!g_light_config) return ESP_FAIL;

    // Chuyển value (0-255) sang duty (0-1023 hoặc max_duty của kênh)
    uint32_t duty = value << 4;  // ví dụ scale value * 16

    // Set duty
    LEDC.channel_group[g_light_config->speed_mode].channel[channel].duty.duty = duty;

    _iot_update_duty(g_light_config->speed_mode, channel);
    return ESP_OK;
}


esp_err_t iot_led_init(ledc_timer_t timer_num, ledc_mode_t speed_mode,
                       uint32_t freq_hz, ledc_clk_cfg_t clk_cfg, ledc_timer_bit_t duty_resolution)
{
    esp_err_t ret = ESP_OK;
    const ledc_timer_config_t ledc_time_config = {
        .speed_mode      = speed_mode,
        .duty_resolution = duty_resolution,
        .timer_num       = timer_num,
        .freq_hz         = freq_hz,
        .clk_cfg         = clk_cfg,
    };
    ret = ledc_timer_config(&ledc_time_config);
    LIGHT_ERROR_CHECK(ret != ESP_OK, ret, "LEDC timer configuration");

    if (g_gamma_table == NULL) {
        g_gamma_table = calloc(GAMMA_TABLE_SIZE + 1, sizeof(uint16_t));
        gamma_table_create(g_gamma_table, GAMMA_CORRECTION);
    }

    if (g_light_config == NULL) {
        g_light_config = calloc(1, sizeof(iot_light_t));
        g_light_config->timer_num  = timer_num;
        g_light_config->speed_mode = speed_mode;

        iot_timer_create(0, DUTY_SET_CYCLE);
    }

    return ESP_OK;
}

esp_err_t iot_led_deinit(void)
{
    if (g_gamma_table) { free(g_gamma_table); g_gamma_table = NULL; }
    if (g_light_config) {
        if (g_fade_esp_timer) { esp_timer_stop(g_fade_esp_timer); esp_timer_delete(g_fade_esp_timer); g_fade_esp_timer = NULL; }
        free(g_light_config);
        g_light_config = NULL;
    }
    return ESP_OK;
}
