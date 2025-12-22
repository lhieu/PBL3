/*
  app_main.c
  CoAP server (GET/PUT) example for libcoap3 + ESP-IDF 5.5
*/

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "coap3/coap.h"

#include "app_storage.h"   // component bạn viết để init NVS
#include "app_driver.h"    // driver (button + light wrapper)

static const char *TAG = "coap_app";

#define LIGHT_SUPPORT_DTLS 0

/* WiFi config (thay bằng thông tin thật của bạn) */
#define LIGHT_ESP_WIFI_SSID     "YOUR-SSID"
#define LIGHT_ESP_WIFI_PASS     "YOUR-PASS"
#define LIGHT_ESP_MAXIMUM_RETRY 5

/* FreeRTOS event group bits */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t s_wifi_event_group;
static int s_retry_num = 0;

/* CoAP payload buffer (shared resource state) */
static char g_payload[128] = "{\"status\": true}";
static size_t g_payload_len = 0;

/* Wi-Fi event handler */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < LIGHT_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *ev = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&ev->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_initialize(void)
{
    s_wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL));
}

static void wifi_start_station(void)
{
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = LIGHT_ESP_WIFI_SSID,
            .password = LIGHT_ESP_WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false,
            },
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_start_station finished.");

    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                          WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                          pdFALSE, pdFALSE, portMAX_DELAY);
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to AP SSID:%s", LIGHT_ESP_WIFI_SSID);
    } else {
        ESP_LOGE(TAG, "Failed to connect to SSID:%s", LIGHT_ESP_WIFI_SSID);
    }
}

/* CoAP GET handler
   Signature matches libcoap3: void (*)(coap_resource_t *, coap_session_t *, const coap_pdu_t *, const coap_string_t *, coap_pdu_t *)
*/
static void coap_get_handler(coap_resource_t *resource,
                             coap_session_t *session,
                             const coap_pdu_t *request,
                             const coap_string_t *query,
                             coap_pdu_t *response)
{
    (void)resource; (void)session; (void)query;

    /* Ensure payload length is set */
    if (g_payload_len == 0) {
        g_payload_len = strlen(g_payload);
    }

    /* Use coap_add_data_blocked_response to handle potentially large responses */
    coap_add_data_blocked_response(request,
                                   response,
                                   COAP_MEDIATYPE_APPLICATION_JSON,
                                   0,                      /* maxage */
                                   g_payload_len,          /* length */
                                   (const uint8_t *)g_payload /* data */);
}

/* CoAP PUT handler */
static void coap_put_handler(coap_resource_t *resource,
                             coap_session_t *session,
                             const coap_pdu_t *request,
                             const coap_string_t *query,
                             coap_pdu_t *response)
{
    (void)resource; (void)session; (void)query;

    size_t size = 0;
    const uint8_t *data = NULL;

    if (coap_get_data(request, &size, &data) && size > 0 && data) {
        /* copy safely into local buffer (truncate if needed) */
        size_t to_copy = (size < sizeof(g_payload)-1) ? size : (sizeof(g_payload)-1);
        memcpy(g_payload, data, to_copy);
        g_payload[to_copy] = '\0';
        g_payload_len = to_copy;

        response->code = COAP_RESPONSE_CODE(204); /* Changed */
        /* Optional: notify observers */
        coap_resource_notify_observers(resource, NULL);
    } else {
        response->code = COAP_RESPONSE_CODE(400); /* Bad request */
    }
}

/* Create and run simple CoAP server (UDP). This function does not return. */
static void coap_server_task(void *arg)
{
    (void)arg;

    coap_context_t *ctx = NULL;
    coap_address_t serv_addr;
    coap_resource_t *resource = NULL;

    /* initialize libcoap logging (optional)
       coap_startup(); // call coap_free_context & coap_cleanup on exit
    */
    coap_startup();

    while (1) {
        coap_endpoint_t *ep = NULL;
        unsigned wait_ms;

        /* setup address */
        coap_address_init(&serv_addr);
        serv_addr.addr.sin6.sin6_family = AF_INET6;
        serv_addr.addr.sin6.sin6_port = htons(COAP_DEFAULT_PORT);

        ctx = coap_new_context(NULL);
        if (!ctx) {
            ESP_LOGE(TAG, "coap_new_context() failed");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

#if LIGHT_SUPPORT_DTLS
        /* If DTLS/PSK wanted, set PSK here (requires coap_dtls support) */
        /* coap_context_set_psk(ctx, "CoAP", (const uint8_t*)psk_key, strlen(psk_key)); */
#endif

        ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
        if (!ep) {
            ESP_LOGE(TAG, "coap_new_endpoint() failed");
            coap_free_context(ctx);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        /* create resource */
        resource = coap_resource_init(coap_make_str_const("light"), 0);
        if (!resource) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            coap_free_context(ctx);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        coap_register_handler(resource, COAP_REQUEST_GET, coap_get_handler);
        coap_register_handler(resource, COAP_REQUEST_PUT, coap_put_handler);

        coap_resource_set_get_observable(resource, 1);
        coap_add_resource(ctx, resource);

        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

        /* server loop */
        while (1) {
            int result = coap_run_once(ctx, wait_ms);
            if (result < 0) {
                break;
            } else if (result && (unsigned)result < wait_ms) {
                wait_ms -= result;
            } else {
                wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
            }
        }

        coap_free_context(ctx);
        ctx = NULL;
        coap_cleanup();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* never reached */
    vTaskDelete(NULL);
}

void app_main(void)
{
    ESP_LOGI(TAG, "app_main start");

    /* NVS and storage init (app_storage should call nvs_flash_init internally) */
    app_storage_init();

    /* driver init (button + light). This will register button callbacks that call app_driver_set_state() */
    if (app_driver_init() != ESP_OK) {
        ESP_LOGW(TAG, "app_driver_init failed");
    }

    /* Wi-Fi init and connect */
    wifi_initialize();
    wifi_start_station();

    /* Start coap server task */
    xTaskCreate(coap_server_task, "coap_server", 8192, NULL, 5, NULL);

    /* main loop - can be used for debug prints */
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        ESP_LOGI(TAG, "app_main alive");
    }
}
