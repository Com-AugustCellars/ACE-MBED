#include "mbed.h"
// #include "dns.h"
#include <string.h>
#include "sn_coap_protocol.h"
#include "sn_coap_header.h"
#include "cn-cbor.h"
#include "oscore.h"
#include "ace.h"

#include "link-mem.h"

extern CoapMessageItem PendingMessages[10];
extern void printCoapMsg(sn_coap_hdr_s * msg);

extern EventQueue MyQUeue;
extern coap_s * coapHandle;
extern coap_version_e coapVersion;

typedef struct {
    char * schema;
    char * address;
    char * port;
    char * path;
} URL;

const char * Psk_Name = "K64F_PSK";
uint8_t Psk_Value[] = { 0xaa, 0xAA, 0xbb, 0xBB, 0xcc, 0xCC, 0xdd, 0xDD, 0xee, 0xEE };


////    UrlParse - parse a URL to pieces
//
//  M00BUG - does not deal with IPv6 addresses.
//

URL * UrlParse(char * urlString)
{
    URL * url_ptr = (URL *) calloc(sizeof(URL), 1);
    int state = 0;
    char ch;
    
    url_ptr->schema = urlString;
    while (*urlString != 0) {
        ch = *urlString;
        if (state == 0) {
            if (ch == ':') {
                *urlString = 0;
                state = 1;
                urlString ++;
            }
            else {
                urlString++;
            }
        }
        else if (state == 1) {
            if (ch == '/' and urlString[1] == '/') {
                urlString += 2;
                url_ptr->address = urlString;
                state = 2;
            }
            else {
                free(url_ptr);
                return NULL;
            }
        }
        else if (state == 2) {
            if (ch == ':') {
                *urlString = 0;
                urlString ++;
                url_ptr->port = urlString;
                state = 3;
            }
            else if (ch == '/') {
                *urlString = 0;
                urlString ++;
                url_ptr->path = urlString;
                return url_ptr;
            }
            else {
                urlString ++;
            }
        }
        else if (state == 3) {
            if (ch == '/') {
                *urlString = 0;
                urlString++;
                url_ptr->path = urlString;
                return url_ptr;
            }
            urlString++;
        }
    }
    free(url_ptr);
    return NULL;
}

extern void AceResponse(int index);
extern void AceRequest(int index);
void TokenResponse(int index);

//// MakeAceRequest
//
//  Given a 4.01 Forbidden response message, try and run ACE to get
//      a better answer
//

bool MakeAceRequest(CoapMessageItem * messageData, const char * audience, const char * scope, coap_msg_delivery callbackSuccess, coap_msg_delivery callbackFail, const char * rsAddress, int rsPort)
{
    sn_coap_hdr_s * response = messageData->sn_coap_response;
    
    // Validate the response to make sure we can use it

    if (response->msg_code != COAP_MSG_CODE_RESPONSE_UNAUTHORIZED ||
        (response->content_format != COAP_CT_NONE && response->content_format != COAP_CT_CBOR &&
         response->content_format != COAP_CT_TEXT_PLAIN) ||
        (response->payload_len == 0)) {
        return false;
    }

    //  Decode to see what the RS is going to tell us.
    //  M00BUG Memory

    cn_cbor * rs_data = cn_cbor_decode(response->payload_ptr, response->payload_len, NULL, NULL);
    if (rs_data == NULL) {
        cn_cbor_free(rs_data, NULL);
        return false;
    }

    //  Create the request we are sending to the AS
    
    cn_cbor * ace_request = cn_cbor_map_create(NULL, NULL);

    //  Copy over NONCE if it exists
    
    cn_cbor * tmp = cn_cbor_mapget_int(rs_data, 5);
    if (tmp != NULL) {
        cn_cbor_mapput_int(ace_request, 5, tmp, NULL, NULL);
    }

    cn_cbor_mapput_int(ace_request, 18, cn_cbor_int_create(2, NULL, NULL), NULL, NULL);  // grant_type
    cn_cbor_mapput_int(ace_request, 3, cn_cbor_string_create(audience, NULL, NULL), NULL, NULL); // audience
    cn_cbor_mapput_int(ace_request, 12, cn_cbor_string_create(scope, NULL, NULL), NULL, NULL); // scope

    // Parse out the URL from the RS

    tmp = cn_cbor_mapget_int(rs_data, 0);
    if (tmp == NULL || tmp->type != CN_CBOR_TEXT) {
        // M00BUG cleanup
        return false;
    }

    char * strUrl = (char *) malloc(tmp->length+1);
    memcpy(strUrl, tmp->v.str, tmp->length);
    strUrl[tmp->length] = 0;
    URL * urlData = UrlParse(strUrl);

    sn_coap_hdr_s * ace_coap_request = (sn_coap_hdr_s*) calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(ace_coap_request);

    ace_coap_request->msg_code = COAP_MSG_CODE_REQUEST_POST;
    if (urlData->path != NULL) {
        ace_coap_request->uri_path_ptr = (uint8_t*) urlData->path;
        ace_coap_request->uri_path_len = strlen(urlData->path);
    }
    else {
        ace_coap_request->uri_path_ptr = (uint8_t *) "/token";
        ace_coap_request->uri_path_len = 6;
    }

    // Calculate the CoAP message size, allocate the memory and build the message
    int cb = cn_cbor_encoder_write(NULL, 0, 0, ace_request);
    uint8_t* message_ptr = (uint8_t*)malloc(cb);
    cn_cbor_encoder_write(message_ptr, 0, cb, ace_request);

    ace_coap_request->payload_ptr = message_ptr;
    ace_coap_request->payload_len = cb;

#if ACE_MBED_TLS
    //  M00BUG - Need to find the key not hard code.
    MyTlsSession * aceTlsSession = MyTlsOpenSession(AsAddress, AsPort, (uint8_t *) Psk_Name, strlen(Psk_Name),
                                                    Psk_Value, sizeof(Psk_Value));
    if (aceTlsSession == NULL) {
        return false;
    }
#else
    OscoreKey * key = FindOscoreKey((uint8_t*) "73.180.8.170:5688", 17);
    if (key == NULL) {
        return false;
    }


    OscoreMsgMatch * match = OscoreRequest(ace_coap_request, key);
#endif

    AceMessageMatch * aceMatch = (AceMessageMatch *) calloc(sizeof(AceMessageMatch), 1);

#if ACE_MBED_TLS
    aceMatch->tlsSession = aceTlsSession;
#else
    memcpy(&(aceMatch->base), match, sizeof(OscoreMsgMatch));
#endif
    aceMatch->callbackFail = callbackFail;
    aceMatch->callbackSuccess = callbackSuccess;
    aceMatch->rsAddress = rsAddress;
    aceMatch->rsPort = rsPort;

#if ACE_MBED_TLS == 0
    free(match);
#endif

    aceMatch->sn_coap_request = messageData->sn_coap_request;
    messageData->sn_coap_request = NULL;

    SendMessage(ace_coap_request, aceMatch, AceResponse, AsAddress, AsPort);

    return true;
}

void AceResponse(int index)
{
    printf("ACE Response received\n");
    printCoapMsg(PendingMessages[index].sn_coap_response);

    if (PendingMessages[index].sn_coap_response->msg_code != COAP_MSG_CODE_RESPONSE_CHANGED) {
        //  we don't know what to do with this.
        return;
    }

    AceMessageMatch * aceMatch = (AceMessageMatch *) PendingMessages[index].callbackData;

#if ACE_MBED_TLS
    sn_coap_hdr_s * response = PendingMessages[index].sn_coap_response;
#else
    sn_coap_hdr_s * response = OscoreResponse(PendingMessages[index].sn_coap_response,
                                              &aceMatch->base);
    if (response == NULL) {
        MyQueue.call(aceMatch->callbackFail, -1);
        return;
    }

    printf("ACE Response - decrypted\n");
    printCoapMsg(response);
#endif

    //  Parse the content as CBOR

    cn_cbor * ace_data = cn_cbor_decode(response->payload_ptr, response->payload_len, NULL, NULL);
    if (ace_data == NULL) {
        cn_cbor_free(ace_data, NULL);
        MyQueue.call(aceMatch->callbackFail, -1);
        return;
    }
    aceMatch->asResponse = ace_data;
    

    //  Post the token to the server

    cn_cbor * token = cn_cbor_mapget_int(ace_data, 19);
    if (token == NULL) {
        //  Must be an error case
        MyQueue.call(aceMatch->callbackFail, -1);
        return;
    }
    
    sn_coap_hdr_s * coap_post_token = (sn_coap_hdr_s *) calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_post_token);

    coap_post_token->msg_code = COAP_MSG_CODE_REQUEST_POST;
    coap_post_token->uri_path_ptr = (uint8_t *) "/authz-info";
    coap_post_token->uri_path_len = 11;

    
    coap_post_token->payload_ptr = (uint8_t *) token->v.bytes;
    coap_post_token->payload_len = token->length;

    SendMessage(coap_post_token, aceMatch, TokenResponse, aceMatch->rsAddress, aceMatch->rsPort);
}

void TokenResponse(int index)
{
    printf("ACE - Repeat original request\n");
    printCoapMsg(PendingMessages[index].sn_coap_response);

    AceMessageMatch * aceMatch = (AceMessageMatch *) PendingMessages[index].callbackData;

    if ((PendingMessages[index].sn_coap_response->msg_code != COAP_MSG_CODE_RESPONSE_CHANGED) &&
        (PendingMessages[index].sn_coap_response->msg_code != COAP_MSG_CODE_RESPONSE_CREATED)) {
        //  Must be an error case
        MyQueue.call(aceMatch->callbackFail, -1);
        //  we don't know what to do with this.
        return;
    }

    //  Build the Security Context

    cn_cbor * cnf = cn_cbor_mapget_int(aceMatch->asResponse, 25);
    cnf = cn_cbor_mapget_int(cnf, 1);

#if ACE_MBED_TLS
    //  Open a new TLS session at this point
    void * match = NULL;
#else
    OscoreKey * rsKey = DeriveOscoreContext(cnf);

    OscoreMsgMatch * match = OscoreRequest(aceMatch->sn_coap_request, rsKey);
#endif
    
    aceMatch->sn_coap_request->msg_id = 0;
    aceMatch->sn_coap_request->token_len = 0;
    free(aceMatch->sn_coap_request->token_ptr);
    aceMatch->sn_coap_request->token_ptr = NULL;

    SendMessage(aceMatch->sn_coap_request, match, aceMatch->callbackSuccess,
                aceMatch->rsAddress, aceMatch->rsPort);
}
