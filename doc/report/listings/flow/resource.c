// Create a new resource
coap_resource_t *resource = coap_resource_init(coap_make_str_const("time"), 0);
if(!resource){
    coap_delete_all_resources(context);
    exit(1);
}

// Document a resource with attributes (describe resource when GET /.well-known/core is called)
coap_add_attr(resource,    coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
coap_add_attr(resource,    coap_make_str_const("rt"),       coap_make_str_const("\"time\""), 0);
coap_add_attr(resource,    coap_make_str_const("if"),        coap_make_str_const("\"GET\""), 0);

// Register resource's data
uint32_t *time = malloc(sizeof(uint32_t));
coap_resource_set_userdata(resource, time);

// Register handlers for methods called on the resourse
coap_register_handler(resource, COAP_REQUEST_GET, hnd_get);

// Set the resource as observable
coap_resource_set_observable(resource, 1);

// Add the resource to the context
coap_add_resource(context, resource);