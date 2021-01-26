typedef struct coap_resource_t {

    void *user_data;

    /* ------------------- Handlers -------------------- */

    coap_method_handler_t handler[7];

    /* -------------------- Helper --------------------- */

    UT_hash_handle    hh;

    /* --------------------- Flags --------------------- */

    unsigned int dirty:1;
    unsigned int partiallydirty:1;
    unsigned int observable:1;
    unsigned int cacheable:1;
    unsigned int is_unknown:1;
    int          flags;

    /* --------------- Resource------------------------- */

    coap_attr_t      *link_attr;
    coap_str_const_t *uri_path;

    /* ------------ Observers-related info ------------- */

    coap_subscription_t *subscribers;  
    unsigned int         observe;

} coap_resource_t;