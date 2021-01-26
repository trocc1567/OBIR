typedef struct coap_pdu_t {
  
    /*
    *                PDU's memory layout
    * 
    * ---------------------------------------------------
    * |<-header->|<-token->|<-options->|0xFF|<-payload->|
    * ---------------------------------------------------
    */

   /* ------------------ Header info ------------------- */

    uint8_t  type;
    uint8_t  code;
    uint16_t tid;
    uint16_t max_delta;
    uint8_t  token_length;
    
    /* ------------------- Size info ------------------- */

    size_t alloc_size;
    size_t used_size;
    size_t max_size;
    
    /* ---------------------- Data --------------------- */

    uint8_t *token;
    uint8_t *data;

} coap_pdu_t;