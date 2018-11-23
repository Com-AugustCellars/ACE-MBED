#include "oscore.h"

#include "mytls.h"

#define COAP_CT_CBOR 60

//
//
//
//

//
//  Declarations to process messages
//

typedef void (*coap_msg_delivery)(int i);

typedef struct coapMessageItem {
    int                 active;
    sn_coap_hdr_s *     sn_coap_request;
    sn_coap_hdr_s *     sn_coap_response;
    int                 messageId;
    coap_msg_delivery   callbackFn;
    void *              callbackData;
    int                 token_len;
    void *              token_ptr;
    //  Add source and dest addresses
    //  Add retransmit information here
} CoapMessageItem;


//
//  Declarations to process messages w/ ACE needed
//

typedef struct {
#if ACE_MBED_TLS
    MyTlsSession *      tlsSession;
#else
    OscoreMsgMatch      base;
#endif
    coap_msg_delivery   callbackFail;
    coap_msg_delivery   callbackSuccess;
    sn_coap_hdr_s *     sn_coap_request;        // Original request
    // const char *        audience;
    // const char *        scope;
    const char *        rsAddress;
    int                 rsPort;
    const cn_cbor *     asResponse;
} AceMessageMatch;

//

bool MakeAceRequest(CoapMessageItem * messageData, const char * audience, const char * scope, coap_msg_delivery callbackSuccess, coap_msg_delivery callbackFail, const char * rsAddress, int rsPort);

extern const char * AsAddress;
extern const int AsPort;
extern EventQueue MyQueue;

extern bool SendMessage(sn_coap_hdr_s * coap_msg_ptr, void * data,  coap_msg_delivery callback, const char * address, int port);

