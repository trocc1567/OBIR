# Include directories
set(include_dirs include)

# Source code files
set(srcs
    "src/address.c"
    "src/async.c"
    "src/block.c"
    "src/coap_hashkey.c"
    "src/coap_io.c"
    "src/coap_session.c"
    "src/coap_time.c"
    "src/coap_debug.c"
    "src/encode.c"
    "src/net.c"
    "src/option.c"
    "src/pdu.c"
    "src/resource.c"
    "src/str.c"
    "src/subscribe.c"
    "src/uri.c"
)

# Register component in the IDF
idf_component_register(
    SRCS "${srcs}"
    INCLUDE_DIRS "${include_dirs}"
    REQUIRES lwip
)

# Originally, this file triggers ggc's 'format-truncation' warning
set_source_files_properties(src/coap_debug.c PROPERTIES COMPILE_FLAGS -Wno-format-truncation)
