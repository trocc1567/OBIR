typedef struct coap_optlist_t {

  struct coap_optlist_t *next;

  uint16_t number;
  size_t length;
  uint8_t *data;

} coap_optlist_t;