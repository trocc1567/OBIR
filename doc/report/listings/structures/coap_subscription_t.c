typedef struct coap_subscription_t {

    struct coap_subscription_t *next;
    coap_session_t *session;

    /* ------------- Basic subscriber info ------------- */

    unsigned int   non_cnt:4;
    unsigned int   fail_cnt:2;
    unsigned int   dirty:1;
    unsigned int   has_block2:1;
    coap_block_t   block2;
    coap_string_t *query;

    /* ------------------ Token info ------------------- */

    size_t token_length;
    unsigned char token[8];

} coap_subscription_t;