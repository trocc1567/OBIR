typedef struct {
  
    coap_opt_t *next_option;

    size_t length;
    uint16_t type;

    unsigned int bad:1;
    unsigned int filtered:1;
    coap_opt_filter_t filter;

} coap_opt_iterator_t;