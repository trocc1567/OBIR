/* debug.c -- debug utilities
 *
 * Copyright (C) 2010--2012,2014--2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see
 * README for terms of use.
 */

# include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>

#include "coap_config.h"
#include "coap_debug.h"
#include "libcoap.h"
#include "block.h"
#include "encode.h"
#include "net.h"

COAP_STATIC_INLINE size_t print_timestamp(char *buf, size_t len, coap_tick_t t);
static size_t print_readable(const uint8_t *data, size_t len, unsigned char *result, size_t buflen, bool encode_always);
static const char *msg_type_string(uint16_t type);
static const char *msg_code_string(uint16_t code);
static const char *msg_option_string(uint8_t code, uint16_t option_type);
static unsigned int print_content_format( unsigned int format_type, unsigned char *result, unsigned int buflen);
COAP_STATIC_INLINE int is_binary(int content_format);


/* ------------------------------------------- [Macrodefinitions] --------------------------------------------- */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/**
 * @brief: Prints @p outbuf string on the output contingent on the global flag
 * 
 * @param outbuf:
 *    buffer to be written
 */
#define COAP_SHOW_OUTPUT(outbuf,level)            \
    do {                                          \
        if(use_fprintf_for_show_pdu)              \
            fprintf(COAP_DEBUG_FD, "%s", outbuf); \
        else                                      \
            coap_log(level, "%s", outbuf);        \
    } while (0)


#define COAP_MAX_LOSS_INTERVALS_NUM 10

/* -------------------------------------------- [Data structures] --------------------------------------------- */

// Current maximum log level
static coap_log_t maxlog = LOG_WARNING;

 // Controls printing PDUs with fprintf
static bool use_fprintf_for_show_pdu = true;

// String names of the @t coap_log_t levels
static const char *loglevels[] = {
  "EMRG", "ALRT", "CRIT", "ERR ", "WARN", "NOTE", "INFO", "DEBG"
};

// Log handler
static coap_log_handler_t log_handler = NULL;

/**
 * @brief: Array of intervals used to control packets' losing rate. Packets sent by the
 *    library are indexed from 0 to UINT_MAX (circularly). Entities in packet_loss_intervals
 *    describe what intervals of apckets should be lost (not sent, int fact).
 *    intervals are ment to be inclusive, i.e. start <= x <= end.
 */
static struct packet_num_interval{
  int start;
  int end;
} packet_loss_intervals[COAP_MAX_LOSS_INTERVALS_NUM];
static int num_packet_loss_intervals = 0;

// Loss level (alternatively) used to control packets' losing rate
static int packet_loss_level = 0;

//
static unsigned int send_packet_count = 0;


/* ----------------------------------------------- [Functions] ------------------------------------------------ */

const char *coap_package_name(void){
    return PACKAGE_NAME;
}


const char *coap_package_version(void){
    return PACKAGE_STRING;
}


void coap_set_show_pdu_output(int use_fprintf){
    use_fprintf_for_show_pdu = use_fprintf;
}


coap_log_t coap_get_log_level(void){
    return maxlog;
}


void coap_set_log_level(coap_log_t level){
    maxlog = level;
}


size_t coap_print_addr(
    const struct coap_address_t *addr, 
    unsigned char *buf, 
    size_t len
){

    // Check idf output buffer is writeable
    if(len == 0)
        return 0;

    in_port_t port;
    unsigned char *p = buf;
    const void *addrptr = NULL;

    // Get address and port depending on the Internet Protocol version
    switch (addr->addr.sa.sa_family) {
        case AF_INET: // IPv4
            addrptr = &addr->addr.sin.sin_addr;
            port = ntohs(addr->addr.sin.sin_port);
            break;
            
        case AF_INET6: // IPv4
            addrptr = &addr->addr.sin6.sin6_addr;
            port = ntohs(addr->addr.sin6.sin6_port);
            break;

        default: // Unknown
            memcpy(buf, "(unknown address type)", min(22, len));
            return min(22, len);
    }

    // If IPv6, print address in form '[x:y:z:...]:port'
    if(addr->addr.sa.sa_family == AF_INET6 && len > 0)
        *p++ = '[';

    // Print address into buffer
    if(inet_ntop(addr->addr.sa.sa_family, addrptr, (char *) p, len - (p - buf)) == 0) {
        perror("coap_print_addr");
        return 0;
    }

    // Update p to point to the terminating '\0'
    p += strnlen((char *) p, len - (p - buf));

    // If IPv6, print address in form '[x:y:z:...]:port'
    if (addr->addr.sa.sa_family == AF_INET6 && buf + len > p)
        *p++ = ']';

    // Append port to the address
    p += snprintf((char *)p, len - (p - buf), ":%d", port);

    return p - buf;
}


void coap_show_pdu(coap_log_t level, const coap_pdu_t *pdu) {

    // Check if level is enough to print
    if(level > coap_get_log_level())
        return;

    // Print basic info about the PDU 
    char outbuf[COAP_DEBUG_BUF_SIZE];
    snprintf(outbuf, sizeof(outbuf), "v:%d t:%s c:%s i:%04x {",
        COAP_DEFAULT_VERSION,
        msg_type_string(pdu->type),
        msg_code_string(pdu->code), 
        pdu->tid
    );

    size_t outbuflen;

    // Print PDU's token in HEX format
    for(unsigned int i = 0; i < pdu->token_length; ++i) {
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf) - outbuflen, "%02x", pdu->token[i]);
    }

    // Close curly bracets around the token
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf) - outbuflen,  "}");

    // Open bracket for PDU's options
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf) - outbuflen,  " [");

    bool has_options = false;
    coap_opt_t *option;
    coap_opt_iterator_t opt_iter;
    int content_format = -1;

    // Show options
    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
    while ((option = coap_option_next(&opt_iter))){

        // Denote at least one option's presence
        if(!has_options)
            has_options = true;
        // Separate subsequent options with coma
        else {
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf) - outbuflen,  ",");
        }

        unsigned char buf[1024];
        size_t buf_len;
        int encode;

        // Search through pdu codes and print desired values into 'buf'
        switch (opt_iter.type){
            case COAP_OPTION_CONTENT_FORMAT:
                content_format = (int)coap_decode_var_bytes(coap_opt_value(option), coap_opt_length(option));
                buf_len = print_content_format(content_format, buf, sizeof(buf));
                break;

            case COAP_OPTION_BLOCK1:
            case COAP_OPTION_BLOCK2:
                buf_len = 
                    snprintf((char *)buf, sizeof(buf), "%u/%c/%u",
                        coap_opt_block_num(option),              /* block number */
                        COAP_OPT_BLOCK_MORE(option) ? 'M' : '_', /* M bit        */
                        (1 << (COAP_OPT_BLOCK_SZX(option) + 4))  /* block size   */
                    );
                break;

            case COAP_OPTION_URI_PORT:
            case COAP_OPTION_MAXAGE:
            case COAP_OPTION_OBSERVE:
            case COAP_OPTION_SIZE1:
            case COAP_OPTION_SIZE2:
                buf_len = 
                    snprintf((char *)buf, sizeof(buf), "%u",
                        coap_decode_var_bytes(coap_opt_value(option),
                        coap_opt_length(option))
                    );
                break;

            default:
                if (opt_iter.type == COAP_OPTION_URI_PATH ||
                    opt_iter.type == COAP_OPTION_PROXY_URI ||
                    opt_iter.type == COAP_OPTION_URI_HOST ||
                    opt_iter.type == COAP_OPTION_LOCATION_PATH ||
                    opt_iter.type == COAP_OPTION_LOCATION_QUERY ||
                    opt_iter.type == COAP_OPTION_URI_QUERY
                ) 
                    encode = 0;
                else
                    encode = 1;
                buf_len = print_readable(
                                coap_opt_value(option), 
                                coap_opt_length(option),
                                buf, sizeof(buf), encode
                            );
                break;
        }

        // Write option's text into the general buffer (outbuf)
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen, " %s:%.*s", 
            msg_option_string(pdu->code, opt_iter.type),
            (int) buf_len, 
            buf
        );
    }

    // Close options bracket
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " ]");

    unsigned char *data;
    size_t data_len;

    // Write informations about payload
    if(coap_get_data(pdu, &data_len, &data)){

        // Preceede payload with double colon
        outbuflen = strlen(outbuf);
        snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  " :: ");

        unsigned char buf[PAYLOAD_MAX_SIZE];

        // Write binary payload
        if (is_binary(content_format)) {

            // Keep pointer to the data and it's length for a while
            int data_len_t = data_len;
            uint8_t *data_t = data;

            // Write information about payload's length
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen, "binary data length %lu\n", (unsigned long) data_len);
            
            // Flush the buffer before loading it with payload
            COAP_SHOW_OUTPUT(outbuf,level);

            // Reset the result buffer's length; start data dump with '<<'
            outbuf[0] = '\000';
            snprintf(outbuf, sizeof(outbuf),  "<< ");

            // Output hex dump of binary data as a continuous entry
            while (data_len--) {
                outbuflen = strlen(outbuf);
                snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen, "%02x ", *data++);
            }

            // Finish data  dump with '>>'
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
            
            // Restore paylod info
            data_len = data_len_t;
            data = data_t;
            
            // Finish payload's dump with a new line
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");

            // Flush the buffer before loading it with readable version of payload
            COAP_SHOW_OUTPUT(outbuf,level);
            
            // Reset the result buffer's length; start data readable dump with '<<'
            outbuf[0] = '\000';
            snprintf(outbuf, sizeof(outbuf),  "<< ");

            // Output readable dump of binary data as a continuous entry
            while (data_len--) {
                outbuflen = strlen(outbuf);
                snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen, " %c ", isprint (*data) ? *data : '.');
                data++;
            }

            // Finish data  dump with '>>'
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  ">>");
        } 
        // Write readable payload
        else if(print_readable(data, data_len, buf, sizeof(buf), false)) {
            outbuflen = strlen(outbuf);
            snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n'%s'", buf);
        }
    }

    // Finish PDU printing with new line character
    outbuflen = strlen(outbuf);
    snprintf(&outbuf[outbuflen], sizeof(outbuf)-outbuflen,  "\n");

    // Flush the result buffer
    COAP_SHOW_OUTPUT(outbuf,level);
}


void coap_set_log_handler(coap_log_handler_t handler) {
    log_handler = handler;
}


void coap_log_impl(coap_log_t level, const char *format, ...) {

    // Check if log can be printed
    if (maxlog < level)
        return;

    // If log_handler is configured, use it to log data
    if (log_handler) {

        char message[COAP_DEBUG_BUF_SIZE];

        // Format variable arguments and write result text into the message buffer 
        va_list ap;
        va_start(ap, format);
        vsnprintf(message, sizeof(message), format, ap);
        va_end(ap);

        // Output buffer
        log_handler(level, message);

    } else {

        char timebuf[32];
        coap_tick_t now;
        
        // Choose output to log on
        FILE *log_fd = (level <= LOG_CRIT) ? COAP_ERR_FD : COAP_DEBUG_FD;

        // Print time info to the output
        coap_ticks(&now);

        if (print_timestamp(timebuf,sizeof(timebuf), now))
            fprintf(log_fd, "%s ", timebuf);

        // Print information about log level
        if (level <= LOG_DEBUG)
            fprintf(log_fd, "%s ", loglevels[level]);

        // Format variable arguments and write result text into the message buffer 
        va_list ap;
        va_start(ap, format);
        vfprintf(log_fd, format, ap);
        va_end(ap);

        fflush(log_fd);
    }
}

int coap_debug_set_packet_loss(const char *loss_level) {
    
    // Convert frst number into numerical value
    const char *p = loss_level;
    char *end = NULL;
    int n = (int)strtol(p, &end, 10);

    // Conversion failed
    if (end == p || n < 0)
        return 0;
    // Conversion succeeded - percentage format
    if (*end == '%') {

        // Truncate loss level to 100%
        if (n > 100)
            n = 100;

        // Set actual loss_level
        packet_loss_level = n * UINT_MAX / 100;

        // Turn off intervals-based loosing
        num_packet_loss_intervals = 0;

        coap_log(LOG_DEBUG, "packet loss level set to %d%%\n", n);
    }
    // Conversion succeeded - coma-separated list format
    else {

        // Negative intervals are illegal
        if (n <= 0)
            return 0;

        int i;

        // Iterate over (up to) all intervals
        for(i = 0; i < COAP_MAX_LOSS_INTERVALS_NUM; ++i){

            packet_loss_intervals[i].start = n;

            // If subsequent numbers are separated by '-', they form an interval
            if (*end == '-') {
                // Parse end of the interval
                p = end + 1;
                n = (int)strtol(p, &end, 10);

                // If parsing failes or end of interval is negative, return error
                if (end == p || n <= 0)
                    return 0;
            }

            // Save end of the interval (it can be equal to the start)
            packet_loss_intervals[i++].end = n;

            // List ended
            if (*end == 0)
                break;
            // List's element are incorectly separated
            if (*end != ',')
                return 0;

            // Convert the next element
            p = end + 1;
            n = (int)strtol(p, &end, 10);
            if (end == p || n <= 0)
                return 0;
        }

        // List is too long or ended with an additional coma
        if (i == COAP_MAX_LOSS_INTERVALS_NUM)
            return 0;

        // Set actual number of intervals set
        num_packet_loss_intervals = i;
    }

    // Reset packets' counter
    send_packet_count = 0;

    return 1;
}


int coap_debug_send_packet(void){

    // Increment packet's counter
    ++send_packet_count;

    // Intervals-based loosing
    if (num_packet_loss_intervals > 0) {
        for(int i = 0; i < num_packet_loss_intervals; i++) 
            if(send_packet_count >= packet_loss_intervals[i].start &&
               send_packet_count <= packet_loss_intervals[i].end)
                return 0;
    }
    // Level-based loosing
    else if( packet_loss_level > 0 ) {
        uint16_t r = 0;
        prng((uint8_t*) &r, 2);
        if( r < packet_loss_level )
            return 0;
    }

    // Packet should be sent
    return 1;
}


/* ------------------------------------------- [Static Functions] --------------------------------------------- */

/**
 * @brief: Prints formatted time data into the @p buf.
 * 
 * @param buf [out]:
 *    buffer to fill
 * @param len:
 *    @p buff's size
 * @param t:
 *    time to format
 * @return COAP_STATIC_INLINE 
 */
COAP_STATIC_INLINE size_t
print_timestamp(char *buf, size_t len, coap_tick_t t){
    time_t now = coap_ticks_to_rt(t);
    struct tm *tmp = localtime(&now);
    return strftime(buf, len, "%b %d %H:%M:%S", tmp);
}


/**
 * @brief: Prints data from the @p data buffer into @p result buffer in the 
 *    human-redable form (i.e. transforming no-printable bytes into their
 *    hex codes)
 * 
 * @param data:
 *    source data buffer
 * @param len:
 *    length of the @p data
 * @param result:
 *    destination buffer
 * @param buflen:
*    length of the @p result
 * @param encode_always:
 *   if true, all bytes from @p data (not only no-printable) are transformed to
 *   the hex code.
 * 
 * @return size_t 
 */
static size_t print_readable(
    const uint8_t *data,
    size_t len,
    unsigned char *result,
    size_t buflen,
    bool encode_always
){
    assert(data || len == 0);
    
    // Check if output buffer can be written
    if (buflen == 0)
        return 0;

    static const uint8_t hex[] = "0123456789ABCDEF";

    // As @p data pointer will move along the source buffer, save the start position
    uint8_t *data_start = data;

    int i = 0;

    // Iterate over all input bytes
    while(data - data_start < len){

        // If @p encode_always flag is cleared (i.e. printable characters are not to be hex-encoded)
        //  and character is printable, copy it from source buffer to result buffer without transforming
        if (!encode_always && isprint(*data)) {

            // Check if result buffer has enough room for additional data and terminating zero
            if (i + 1 < buflen) { 
                result[i++] = *data++;
            } else
                break;
        } 
        // If @p encode_always flag is set, or character is not printable, copy
        // it from source buffer to result buffer with transformation
        //
        // Check if result buffer has enough room for additional data and terminating zero
        // (printing a byte in hex requires 4 bytes itself)
        else if (i + 4 < buflen) {
                result[i++] = '0';
                result[i++] = 'x';
                result[i++] = hex[(*data & 0xf0) >> 4];
                result[i++] = hex[*data++ & 0x0f];
        } else
            break;
    }

    // Add a terminating zero
    result[i] = '\0'; 

    return i;
}


/** 
 * @brief: Returns a textual description of the message type @p t. 
 * 
 * @param type:
 *    type of the message; one of values COAP_MESSAGE_*
 * @returns:
 *    pointer to the statically allocated buffer containing readable
 *    representation of the type
 */
static 
const char *msg_type_string(uint16_t type){
    static const char *types[] = { "CON", "NON", "ACK", "RST", "???" };
    return types[min(type, sizeof(types)/sizeof(char *) - 1)];
}


/**
 * @brief:  Returns a textual description of the method or response code.
 * 
 * @param code:
 *    code of the method/response; one of COAP_REQUEST_* ora COAP_SIGNALING* values
 * @returns:
 *    pointer to the statically allocated buffer containing readable representation 
 *    of the method/response code
 */
static const char *msg_code_string(uint16_t code){

    static const char *methods[] = { "0.00", "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "iPATCH" };
    static char buf[5];

    // Methode's code
    if (code < sizeof(methods)/sizeof(const char *))
        return methods[code];
    // Unknown code
    else {
        snprintf(buf, sizeof(buf), "%u.%02u", code >> 5, code & 0x1f);
        return buf;
    }
}


/** 
 * @brief: Returns a textual description of the option name. 
 * 
 * @param code:
 *    response code; one of COAP_SIGNALING_* values
 * 
 * @param option_type:
 *    decoded (i.e. absolute, no delta-coded) option's code
 */
static const char *
msg_option_string(uint8_t code, uint16_t option_type) {
  
    // Local structure describing an option
    struct option_desc_t {
        uint16_t type;
        const char *name;
    };

    // Options descriptions
    static struct option_desc_t options[] = {
        { COAP_OPTION_IF_MATCH, "If-Match" },
        { COAP_OPTION_URI_HOST, "Uri-Host" },
        { COAP_OPTION_ETAG, "ETag" },
        { COAP_OPTION_IF_NONE_MATCH, "If-None-Match" },
        { COAP_OPTION_OBSERVE, "Observe" },
        { COAP_OPTION_URI_PORT, "Uri-Port" },
        { COAP_OPTION_LOCATION_PATH, "Location-Path" },
        { COAP_OPTION_URI_PATH, "Uri-Path" },
        { COAP_OPTION_CONTENT_FORMAT, "Content-Format" },
        { COAP_OPTION_MAXAGE, "Max-Age" },
        { COAP_OPTION_URI_QUERY, "Uri-Query" },
        { COAP_OPTION_ACCEPT, "Accept" },
        { COAP_OPTION_LOCATION_QUERY, "Location-Query" },
        { COAP_OPTION_BLOCK2, "Block2" },
        { COAP_OPTION_BLOCK1, "Block1" },
        { COAP_OPTION_PROXY_URI, "Proxy-Uri" },
        { COAP_OPTION_PROXY_SCHEME, "Proxy-Scheme" },
        { COAP_OPTION_SIZE1, "Size1" },
        { COAP_OPTION_SIZE2, "Size2" },
        { COAP_OPTION_NORESPONSE, "No-Response" }
    };
    
    // Select options set depending on the actual code
    size_t options_num;
    struct option_desc_t *opts;

    options_num = sizeof(options) / sizeof(struct option_desc_t);
    opts = options;


    // Look for desired option's description
    for (size_t i = 0; i < options_num; i++)
        if (option_type == opts[i].type)
            return opts[i].name;

    // If unknown option type, just print to buf
    static char buf[6];
    snprintf(buf, sizeof(buf), "%u", option_type);
    return buf;
}


/**
 * @brief: Prints human-redeable description of the format-type to the
 *    given buffer.
 * 
 * @param format_type:
 *    desired format-type; one of COAP_MEDIATYPE_* values
 * @param result [out]:
 *    result buffer
 * @param buflen:
 *    size of the result buffer
 * @returns:
 *    number of bytes written to the @p result
 * 
 */
static unsigned int
print_content_format(
    unsigned int format_type,
    unsigned char *result, 
    unsigned int buflen
){
    // Check if result buffer is writteable
    if(buflen == 0)
        return 0;
    
    // Local structure describing format-types
    struct desc_t {
        unsigned int type;
        const char *name;
    };

    // Actual format-types
    static struct desc_t formats[] = {
        { COAP_MEDIATYPE_TEXT_PLAIN, "text/plain" },
        { COAP_MEDIATYPE_APPLICATION_LINK_FORMAT, "application/link-format" },
        { COAP_MEDIATYPE_APPLICATION_XML, "application/xml" },
        { COAP_MEDIATYPE_APPLICATION_OCTET_STREAM, "application/octet-stream" },
        { COAP_MEDIATYPE_APPLICATION_EXI, "application/exi" },
        { COAP_MEDIATYPE_APPLICATION_JSON, "application/json" },
        { COAP_MEDIATYPE_APPLICATION_CBOR, "application/cbor" },
        { COAP_MEDIATYPE_APPLICATION_COSE_SIGN, "application/cose; cose-type=\"cose-sign\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_SIGN1, "application/cose; cose-type=\"cose-sign1\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT, "application/cose; cose-type=\"cose-encrypt\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_ENCRYPT0, "application/cose; cose-type=\"cose-encrypt0\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_MAC, "application/cose; cose-type=\"cose-mac\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_MAC0, "application/cose; cose-type=\"cose-mac0\"" },
        { COAP_MEDIATYPE_APPLICATION_COSE_KEY, "application/cose-key" },
        { COAP_MEDIATYPE_APPLICATION_COSE_KEY_SET, "application/cose-key-set" },
        { COAP_MEDIATYPE_APPLICATION_SENML_JSON, "application/senml+json" },
        { COAP_MEDIATYPE_APPLICATION_SENSML_JSON, "application/sensml+json" },
        { COAP_MEDIATYPE_APPLICATION_SENML_CBOR, "application/senml+cbor" },
        { COAP_MEDIATYPE_APPLICATION_SENSML_CBOR, "application/sensml+cbor" },
        { COAP_MEDIATYPE_APPLICATION_SENML_EXI, "application/senml-exi" },
        { COAP_MEDIATYPE_APPLICATION_SENSML_EXI, "application/sensml-exi" },
        { COAP_MEDIATYPE_APPLICATION_SENML_XML, "application/senml+xml" },
        { COAP_MEDIATYPE_APPLICATION_SENSML_XML, "application/sensml+xml" },
        { 75, "application/dcaf+cbor" }
    };

    ;

    // Search format_type in list of known content formats
    for (size_t i = 0; i < sizeof(formats)/sizeof(struct desc_t); i++)
        if (format_type == formats[i].type)
            return snprintf((char *)result, buflen, "%s", formats[i].name);

    // For unknown content format, just print numeric value to buf the buf
    return snprintf((char *)result, buflen, "%d", format_type);
}


/**
 * @param content_format:
 *    content-format; one of COAP_MEDIATYPE_* values
 * @returns:
 *    1 if the given @p content_format is either unknown or known to carry binary data
 *    0 if it is printable data which is also assumed if @p content_format is -1.
 */
COAP_STATIC_INLINE int
is_binary(int content_format){
    return !(
        content_format == -1                                     ||
        content_format == COAP_MEDIATYPE_TEXT_PLAIN              ||
        content_format == COAP_MEDIATYPE_APPLICATION_LINK_FORMAT ||
        content_format == COAP_MEDIATYPE_APPLICATION_XML         ||
        content_format == COAP_MEDIATYPE_APPLICATION_JSON
    );
}
