idf_component_register(
    SRCS 
        "coap_session.c"        
        "coap_pdu.c"
        "coap_str.c"
        "coap_resource.c"
        "coap_dtls.c"   # nếu dùng DTLS
        # ... thêm các file khác từ libcoap/src nếu cần
    INCLUDE_DIRS "include"
    REQUIRES mbedtls  # nếu dùng DTLS
)
