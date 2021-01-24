
#include <string.h>            // Basic string operations
#include <errno.h>             // erno variable
#include "coap.h"              // CoAP implementation
#include "include/rpn_stack.h"
#include "lwip/apps/sntp.h"
#include "coap_handlers.h"


/* --------------------------- Global & static definitions --------------------------- */

// Source file's tag
static char *TAG = "coap_handlers";

// '/colour' resource buffer
enum{R, G, B};
uint8_t colour[3] = {0};

// '/rpn' expressions array 
#define RPN_MAX_SIZE 10
#define EXP_MAX_SIZE 30
char rpn_col[RPN_MAX_SIZE][EXP_MAX_SIZE]={NULL};
uint8_t rpn_expression_count = 0;
/* ---------------------------------------- Code -------------------------------------- */

/**
 * @brief Initializes resources present on the server
 * 
 * @param context Pointer to the CoAP context stack
 * @returns 0 on success and a negative number at failure. At the failure
 *  all resources are deleted from the context.
 */
int resources_init(coap_context_t *context){

    coap_resource_t *resource = NULL;

    /* =================================================== */
    /*            Resource: 'time' (observable)            */
    /* =================================================== */

    // Synchronise system time with global
    if(! sntp_enabled() ){
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "pool.ntp.org");
        sntp_init();
    }

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("time"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,    coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,    coap_make_str_const("rt"),       coap_make_str_const("\"time\""), 0);
    coap_add_attr(resource,    coap_make_str_const("if"),        coap_make_str_const("\"GET\""), 0);

    // Register handlers for methods called on the resourse
    coap_register_handler(resource, COAP_REQUEST_GET, hnd_get);

    // Set the resource as observable
    coap_resource_set_get_observable(resource, 1);

    // Add the resource to the context
    coap_add_resource(context, resource);


    /* =================================================== */
    /*               Resource: 'colour'                    */
    /* =================================================== */

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("colour"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,  coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,  coap_make_str_const("rt"),     coap_make_str_const("\"colour\""), 0);
    coap_add_attr(resource,  coap_make_str_const("if"),    coap_make_str_const("\"GET PUT\""), 0);
    coap_add_attr(resource, coap_make_str_const("put"),   coap_make_str_const("\"%d %d %d\""), 0);
    

    // Register handlers for methods called on the resourse
    coap_register_handler(resource,    COAP_REQUEST_GET, hnd_get);
    coap_register_handler(resource,    COAP_REQUEST_PUT, hnd_put);

    // Set the resource as observable
    coap_resource_set_get_observable(resource, 1);

    // Add the resource to the context
    coap_add_resource(context, resource);
    
    /* =============================================================== */
    /*               Resource: 'RPN' (Reverse Polish Notation)         */
    /* =============================================================== */

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("rpn"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,  coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,  coap_make_str_const("rt"),     coap_make_str_const("\"rpn\""), 0);
    coap_add_attr(resource,  coap_make_str_const("if"),    coap_make_str_const("\"GET PUT\""), 0);
    coap_add_attr(resource, coap_make_str_const("put"),   coap_make_str_const("\"%s\""), 0);
    

    // Register handlers for methods called on the resourse
    coap_register_handler(resource,    COAP_REQUEST_GET, hnd_get);
    coap_register_handler(resource,    COAP_REQUEST_PUT, hnd_put);

    // Set the resource as observable
    coap_resource_set_get_observable(resource, 0);

    // Add the resource to the context
    coap_add_resource(context, resource);
    
    /* =============================================================== */
    /*               Resource: 'mectric1'					           */
    /* =============================================================== */

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("metrics/metric1"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,  coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,  coap_make_str_const("rt"),     coap_make_str_const("\"metric1\""), 0);
    coap_add_attr(resource,  coap_make_str_const("if"),    coap_make_str_const("\"GET\""), 0);
    

    // Register handlers for methods called on the resourse
    coap_register_handler(resource,    COAP_REQUEST_GET, hnd_get);

    // Add the resource to the context
    coap_add_resource(context, resource);
    
    /* =============================================================== */
    /*               Resource: 'mectric2'					           */
    /* =============================================================== */

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("metrics/metric2"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,  coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,  coap_make_str_const("rt"),     coap_make_str_const("\"metric2\""), 0);
    coap_add_attr(resource,  coap_make_str_const("if"),    coap_make_str_const("\"GET\""), 0);
    

    // Register handlers for methods called on the resourse
    coap_register_handler(resource,    COAP_REQUEST_GET, hnd_get);

    // Add the resource to the context
    coap_add_resource(context, resource);
    
    /* =============================================================== */
    /*      Resource: 'mectric3' (Resource with long access time)	   */
    /* =============================================================== */

    // Create a new resource
    if( !(resource = coap_resource_init(coap_make_str_const("metrics/metric3"), 0)) ){
        coap_delete_all_resources(context);
        return 0;
    }

    // Document a resource with attributes (describe resource when GET /.well-known/core is called)
    coap_add_attr(resource,  coap_make_str_const("ct"), coap_make_str_const("\"plain text\""), 0);
    coap_add_attr(resource,  coap_make_str_const("rt"),     coap_make_str_const("\"metric3\""), 0);
    coap_add_attr(resource,  coap_make_str_const("if"),    coap_make_str_const("\"GET\""), 0);
    

    // Register handlers for methods called on the resourse
    coap_register_handler(resource,    COAP_REQUEST_GET, hnd_get);

    // Add the resource to the context
    coap_add_resource(context, resource);

    return 0;
}

/**
 * @brief Clears all resources from the context and closes SNTP deamon.
 * 
 * @param context Context related with resources to delete
 */
void resources_deinit(coap_context_t *context){
    sntp_stop();
    if(context)
        coap_delete_all_resources(context);
}

/**
 * @brief Handler for GET request
 */
void hnd_get(
    coap_resource_t *resource,
    coap_session_t *session, 
    coap_pdu_t *request,
    coap_binary_t *token, 
    coap_string_t *query,
    coap_pdu_t *response
){

    // Handle ' GET /time' request
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("time")) ){
        
        // Get currnt time
        time_t now;
        time(&now);
        
        // Transform us time into string-formatted tm struct 
        char strftime_buf[100];
        struct tm timeinfo;
        localtime_r(&now, &timeinfo);
        size_t length = 
            strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo);

        // Send data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            length,
            (uint8_t *) strftime_buf
        );
    }    
    // Handle ' GET /colour' request
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("colour")) ){
        
        // Construct text from the resource
        char colour_buf[18];
        size_t size = snprintf(colour_buf, 18, "R:%d G:%d B:%d", colour[R], colour[G], colour[B]);

        // Send data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            size,
            (uint8_t *) colour_buf
        );
    }
    // Handle ' GET /rpn' requests
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("rpn")) ){
		
		char rpn_buf[300]={NULL};
		size_t dlugosc;
		
		//GET with query 'all': send all expressions
		if (strcmp(query->s, "all")==0)
		{
			//Collecting all expressions and writing to one bufor
			uint8_t i, ct;
			for (i=0; i<rpn_expression_count; i++)
			{
				char exp_buf[strlen(rpn_col[i]+1)];
				ct=snprintf(exp_buf, 31, "%s\n", rpn_col[i]);
				strncat(rpn_buf, exp_buf, ct+1);
			}
			dlugosc=strlen(rpn_buf);
		}
		// GET qith query: value of expression
		else
		{
			char * f_ampersand;
			//Parse URI-Query
			char query_bufor[query->length + 1];
			strcpy(query_bufor, query->s);
			char * bufor_n;
			//Reading n variable
			bufor_n = strstr(query_bufor,"n=");
			if (bufor_n==NULL) dlugosc = snprintf(rpn_buf, 7, "No n");
			else {
				bufor_n+=2;
				f_ampersand = strchr(query_bufor, '&');
				if (f_ampersand>bufor_n)
				strncpy(bufor_n, bufor_n, f_ampersand-bufor_n+1);
				uint8_t n=atoi(bufor_n);
				//Reading wyr variable
				char * bufor_wyr;
				bufor_wyr = strstr(query_bufor,"wyr=");
				if (bufor_wyr==NULL) dlugosc = snprintf(rpn_buf, 9, "No wyr");
				
				else {
					bufor_wyr+=4;
					f_ampersand = strchr(query_bufor, '&');
					if (f_ampersand>bufor_wyr)
					strncpy(bufor_wyr, bufor_wyr, f_ampersand-bufor_wyr+1);
					uint8_t wyr=atoi(bufor_wyr);
					//Checking wyr variable
					if (wyr>rpn_expression_count) dlugosc = snprintf(rpn_buf, 11, "Wrong wyr");
				// Construct text from the resource, if n and wyr are OK, counting a RPN for n and wyr
			
				 else dlugosc = snprintf(rpn_buf, 50, "Expression %d for n=%d is %d",wyr, n, getRPN(rpn_col[wyr-1], n));
				}
			}
		}
		

        // Send data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            dlugosc,
            (uint8_t *) rpn_buf
        );
	}
	
	// Handle ' GET /metrics/metric1' request
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("metrics/metric1")) ){
        
        
        // Send data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            1,
            (uint8_t *) "1"
        );
    }
    
    // Handle ' GET /metrics/metric2' request
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("metrics/metric2")) ){
        
		
        // Send data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            1,
            (uint8_t *) "2"
        );
    }
    
    // Handle ' GET /metrics/metric3' request
    if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("metrics/metric3")) ){
        //Sending empty answer
        coap_send_ack(session, request);
        
        //Sending data with dedicated function
        coap_add_data_blocked_response(
            resource,
            session,
            request,
            response,
            token,
            COAP_MEDIATYPE_TEXT_PLAIN,
            0,
            1,
            (uint8_t *) "3"
        );
    }
}

/**
 * @brief Handler for PUT request
 */
void hnd_put(
    coap_resource_t *resource,
    coap_session_t *session,
    coap_pdu_t *request,
    coap_binary_t *token,
    coap_string_t *query,
    coap_pdu_t *response
){
	//PUT for '/colour' resource
	if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("colour")) )
	{
		// Get requests's payload
		size_t size;
		uint8_t *data;
		coap_get_data(request, &size, &data);

		// If data parsing fails (or no payload is present) set response code to 2.04 (Changed)
		if (size == 0)
			response->code = COAP_RESPONSE_CODE(400);
		// Otherwise, try to parse data
		else {
			
			// Create colour backup
			uint8_t colour_bck[3];
			colour_bck[R] = colour[R];
			colour_bck[G] = colour[G];
			colour_bck[B] = colour[B];

			// By default, set response code to 2.04 (Changed)
			response->code = COAP_RESPONSE_CODE(204);

			// Parse three integers
			for(int i = 0; i < 3; ++i){

				char * endp;
				errno = 0;
				long col = strtol((char *) data, &endp, 10);

				// If parsing failed reasume backup and call error
				if((char *) data == endp){
					colour[R] = colour_bck[R];
					colour[G] = colour_bck[G];
					colour[B] = colour_bck[B];
					response->code = COAP_RESPONSE_CODE(400);
					break;
				} 
				// If parsed value is out of range, cut it to the range's edge 
				else if( col < 0)
					colour[i] = 0;            
				else if( col > 255)
					colour[i] = 255;
				// Otherwise, set colour value
				else
					colour[i] = (uint8_t) col;

				data = (uint8_t *) endp;
			}

			// Notify observers, if any
			if(response->code == COAP_RESPONSE_CHANGED)        
				coap_resource_notify_observers(resource, NULL);
		}
	}
	//PUT for '/rpn' resource
	if( resource == coap_get_resource_from_uri_path(session->context, coap_make_str_const("rpn")) )
	{
		// Get requests's payload
		size_t size;
		uint8_t *data;
		coap_get_data(request, &size, &data);

		// If data parsing fails (or no payload is present) set response code to 2.04 (Changed)
		if (size == 0 ||rpn_expression_count>=RPN_MAX_SIZE-1)
			response->code = COAP_RESPONSE_CODE(400);
		// Otherwise, try to parse data
		else {
			// By default, set response code to 2.04 (Changed)
			response->code = COAP_RESPONSE_CODE(204);
			//Writing new RPN expression to array
			strcpy(rpn_col[rpn_expression_count], data);
			rpn_expression_count++;
			}

			// Notify observers, if any
			if(response->code == COAP_RESPONSE_CHANGED)        
				coap_resource_notify_observers(resource, NULL);
		}
	}

