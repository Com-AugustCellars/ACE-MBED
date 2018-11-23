/*
 * PackageLicenseDeclared: Apache-2.0
 * Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string>
#include "mbed.h"
#include "mbed_mem_trace.h"
#include "EthernetInterface.h"
#include "randLIB.h"

#if ACE_MBED_TLS
#include "mytls.h"
#endif

//#include "sn_nsdl.h"
#include "sn_coap_protocol.h"
#include "sn_coap_header.h"
#include "oscore.h"
//#include "dns.h"
#include "ace.h"

UDPSocket socket;           // Socket to talk CoAP over
Thread recvfromThread;      // Thread to receive messages over CoAP
Thread myMainThread(osPriorityNormal, 8*1024, NULL);

EthernetInterface net;

DigitalOut red(LED1);
DigitalOut blue(LED2);
DigitalOut green(LED3);

extern void OscoreGet();
EventQueue MyQueue;

extern void DoOscoreGet();
extern void DoOscoreGetResponse(int i);

extern void DoAceGet();
extern void DoAceGetResponse(int i);

struct coap_s* coapHandle;
coap_version_e coapVersion = COAP_VERSION_1;

const char * RsAddress = "192.168.1.117";
const int RsPort = 5683;
const char * AsAddress = "192.168.1.117";
#if ACE_MBED_TLS
const int AsPort = 5689;
#else
const int AsPort = 5688;
#endif

// CoAP HAL
void* coap_malloc(uint16_t size) {
    return malloc(size);
}

void coap_free(void* addr) {
    free(addr);
}


uint8_t coap_tx_cb(uint8_t * msg_ptr, uint16_t msg_len, sn_nsdl_addr_s *c, void *d)
{
    int scount = socket.sendto((const char *) c->addr_ptr, c->port, msg_ptr, msg_len);
    printf("Sent %d bytes to coap://%s:%d\n", scount, c->addr_ptr, c->port);

    return scount;
}

int8_t coap_rx_cb(sn_coap_hdr_s *a, sn_nsdl_addr_s *b, void *c) {
    printf("coap rx cb\n");
    return 0;
}

CoapMessageItem PendingMessages[10];


void sn_coap_protocol_send_ack(struct coap_s *handle, uint16_t msg_id, uint8_t * token_ptr, int token_len, sn_nsdl_addr_s *addr_ptr, void *param)
{
    uint8_t packet_ptr[4+8];

    /* Add CoAP version and message type */
    packet_ptr[0] = COAP_VERSION_1;
    packet_ptr[0] |= COAP_MSG_TYPE_ACKNOWLEDGEMENT;
    packet_ptr[0] |= token_len;

    /* Add message code */
    packet_ptr[1] = COAP_MSG_CODE_EMPTY;

    /* Add message ID */
    packet_ptr[2] = msg_id >> 8;
    packet_ptr[3] = (uint8_t)msg_id;

    // Add token
    if (token_len > 0) {
        memcpy(&packet_ptr[4], token_ptr, token_len);
    }

    /* Send ACK */
    // handle->sn_coap_tx_callback(packet_ptr, 4+token_len, addr_ptr, param);
    coap_tx_cb(packet_ptr, 4+token_len, addr_ptr, param);

}


void printCoapMsg(sn_coap_hdr_s * msg)
{
    // We know the payload is going to be a string
    // std::string payload((const char*)msg->payload_ptr, msg->payload_len);

    printf("\tparse status:     %d\n", msg->coap_status);
    printf("\tmsg_id:           %d\n", msg->msg_id);
    printf("\tmsg_code:         %d.%d\n", msg->msg_code >> 5, msg->msg_code & 0x1f);
    printf("\tcontent_format:   %d\n", msg->content_format);
    printf("\tpayload_len:      %d\n", msg->payload_len);
    printf("\tcontent type:     %d\n", msg->content_format);
    // printf("\tpayload:          %s\n", payload.c_str());
    printf("\toptions_list_ptr: %p\n", msg->options_list_ptr);
    fflush(stdout);
}

void print_memory_info()
{
    int cnt = osThreadGetCount();
    mbed_stats_stack_t * stats = (mbed_stats_stack_t*) malloc(cnt * sizeof(mbed_stats_stack_t));

    cnt = mbed_stats_stack_get_each(stats, cnt);
    for (int i=0; i<cnt; i++) {
        printf("Thread: 0x%lX, Stack size: %lu / %lu\n", stats[i].thread_id, stats[i].max_size, stats[i].reserved_size);
    }
    free(stats);

    // Grab the heap stats
    mbed_stats_heap_t heap_stats;
    mbed_stats_heap_get(&heap_stats);
    printf("Heaad size: %lu / %lu bytes\n", heap_stats.current_size, heap_stats.reserved_size);
}

//  Event queue

//EventQueue * queue = &Queue;

// Main function for the recvfrom thread
void recvfromMain()
{
    int i;
    SocketAddress addr;
    uint8_t* recv_buffer = (uint8_t*)malloc(1280); // Suggested is to keep packet size under 1280 bytes

    nsapi_size_or_error_t ret;

    while ((ret = socket.recvfrom(&addr, recv_buffer, 1280)) >= 0) {
        // to see where the message came from, inspect addr.get_addr() and addr.get_port()


        // printf("Received a message of length '%d'\n", ret);

        sn_nsdl_addr_s srcAddr = {0, SN_NSDL_ADDRESS_TYPE_IPV4, addr.get_port(), (uint8_t *) addr.get_ip_address()};
        srcAddr.addr_len = strlen((char *) srcAddr.addr_ptr);

        sn_coap_hdr_s* parsed = sn_coap_protocol_parse(coapHandle, &srcAddr, ret, recv_buffer, NULL);
        if (parsed == NULL) {
            continue;
        }

        if (parsed->msg_type == COAP_MSG_TYPE_CONFIRMABLE) {
            sn_coap_protocol_send_ack(coapHandle, parsed->msg_id, parsed->token_ptr, parsed->token_len, &srcAddr, NULL);
        }


        if (parsed->coap_status == COAP_STATUS_PARSER_DUPLICATED_MSG) {
            free(parsed);
            continue;
        }

        if (parsed->msg_code == COAP_MSG_CODE_EMPTY) {
            //  For now ignore any ACKs
            free(parsed);
            continue;
        }

        for (i=0; i<10; i++) {
            if (PendingMessages[i].active &&
                PendingMessages[i].token_len == parsed->token_len &&
                memcmp(PendingMessages[i].token_ptr, parsed->token_ptr, parsed->token_len) == 0) {
                
                PendingMessages[i].active = false;
                PendingMessages[i].sn_coap_response = parsed;
                PendingMessages[i].token_len = 0;
                if (PendingMessages[i].token_ptr != NULL) {
                    free(PendingMessages[i].token_ptr);
                    PendingMessages[i].token_ptr = NULL;
                }

                MyQueue.call(PendingMessages[i].callbackFn, i);
                break;
            }
        }

        if (i == 10) {
            free(parsed);
        }
    }

    free(recv_buffer);

    printf("UDPSocket::recvfrom failed, error code %d. Shutting down receive thread.\n", ret);
    fflush(stdout);

}

bool SendMessage(sn_coap_hdr_s * coap_msg_ptr, void * data,  coap_msg_delivery callback, const char * address, int port)
{

    if (coap_msg_ptr->token_len == 0) {
        coap_msg_ptr->token_ptr = (uint8_t*) malloc(2);
        *((uint16_t *) coap_msg_ptr->token_ptr) = randLIB_get_16bit();
        coap_msg_ptr->token_len = 2;
    }
    
    // Calculate the CoAP message size, allocate the memory and build the message
    uint16_t message_len = sn_coap_builder_calc_needed_packet_data_size(coap_msg_ptr);
    if (message_len <= 0) {
        // M00BUG cleanup
        return false;
    }
    
    printf("Calculated message length: %d bytes\n", message_len);

    uint8_t* message_ptr = (uint8_t*)malloc(message_len);
    if (sn_coap_builder(message_ptr, coap_msg_ptr) < 0) {
        // M00BUG clean up
        return false;
    }
        

    // Uncomment to see the raw buffer that will be sent...
    // printf("Message is: ");
    // for (size_t ix = 0; ix < message_len; ix++) {
    //     printf("%02x ", message_ptr[ix]);
    // }
    // printf("\n");

    int i;
    for (i=0; i<10; i++) {
        if (PendingMessages[i].active == 0) break;
    }

    if (i == 10) return false;

    PendingMessages[i].active = true;
    PendingMessages[i].sn_coap_request = coap_msg_ptr;
    PendingMessages[i].messageId = coap_msg_ptr->msg_id;
    PendingMessages[i].callbackFn = callback;
    PendingMessages[i].callbackData = data;
    PendingMessages[i].token_len = coap_msg_ptr->token_len;
    if (coap_msg_ptr->token_len > 0) {
        PendingMessages[i].token_ptr = calloc(coap_msg_ptr->token_len, 1);
        memcpy(PendingMessages[i].token_ptr, coap_msg_ptr->token_ptr, coap_msg_ptr->token_len);
    }

    sn_nsdl_addr_s dst_addr = {(uint8_t) strlen(address), SN_NSDL_ADDRESS_TYPE_IPV4, port, (uint8_t *) address};

    int cb = sn_coap_protocol_build(coapHandle, &dst_addr, message_ptr, coap_msg_ptr, NULL);

    int scount;
    if (cb > 0) {
#if ACE_MBED_TLS
        AceMessageMatch * aceMatch = (AceMessageMatch *) data;
        
        if ((data != NULL) && (aceMatch->tlsSession != NULL)) {
            scount = MyTlsWrite(&((AceMessageMatch *) data)->tlsSession->tlsContext, message_ptr, message_len);
        }
        else {
            scount = socket.sendto(address, port, message_ptr, message_len);
        }
#else
        scount = socket.sendto(address, port, message_ptr, message_len);
#endif
        printf("Sent %d bytes to coap://%s:%d\n", scount, address, port);
    }

    free(message_ptr);
    if (cb <= 0) {
        PendingMessages[i].active = false;
        return false;
    }
    return scount == message_len;
}

int DispatchState = 0;

void DispatchNext()
{
    printf("*** DISPATCH NEXT %d\n", DispatchState);
    print_memory_info();
    
    switch (DispatchState) {
    case 0:
#if ACE_MBED_TLS
        DispatchState += 1;
        DispatchNext();
#else
        DoOscoreGet();
#endif
        break;

    case 1:
        DoAceGet();
        break;

    default:
        break;
    }
    DispatchState += 1;
}

void DoGetResponse(int index)
{
    printf("\nGET RESPONSE\n");
    
    printCoapMsg(PendingMessages[index].sn_coap_response);

    if (PendingMessages[index].sn_coap_response->msg_code == COAP_MSG_CODE_RESPONSE_UNAUTHORIZED) {
        MakeAceRequest(&PendingMessages[index], "aud2", "read",
                       DoGetResponse, DoGetResponse, RsAddress, RsPort);
    }

    DispatchNext();
}

void DoGetMessage()
{
    // Path to the resource we want to retrieve
    const char* coap_uri_path = "/oscore/hello/1"; //  "/ace/helloWorld";

    // See ns_coap_header.h
    sn_coap_hdr_s *coap_res_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_res_ptr);

    coap_res_ptr->uri_path_ptr = (uint8_t*)coap_uri_path;       // Path
    coap_res_ptr->uri_path_len = strlen(coap_uri_path);
    coap_res_ptr->msg_code = COAP_MSG_CODE_REQUEST_GET;         // CoAP method

    if (!SendMessage(coap_res_ptr, NULL, DoGetResponse, RsAddress, RsPort)) {
        free(coap_res_ptr);
    }
}

void UpdateFlash()
{
    //  Get the size of the data to write

    int cbToWrite = 0;

    cbToWrite += WriteKeysToBuffer(NULL, 0);

    //  Allocate the buffer and then get the data

    uint8_t * pbToWrite = (uint8_t *) malloc(cbToWrite);

    uint32_t cbWritten = 0;
    cbWritten += WriteKeysToBuffer(pbToWrite+cbWritten, cbToWrite);

    //  Get the location to write to

    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    const uint32_t sector_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    // int page_size = flash.get_page_size();

    //  Check that we are smaller than the page size

    if (cbWritten > sector_size) {
        exit(1);
    }

    flash.erase(address, sector_size);
    flash.program(pbToWrite, address, cbToWrite);
    flash.deinit();

    free(pbToWrite);
}

void ReadFlash()
{
    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    const uint32_t sector_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    // int page_size = flash.get_page_size();
    uint8_t * buffer = (uint8_t *) address;

    uint32_t cbUsed = 0;
    cbUsed += ReadKeysFromBuffer(buffer + cbUsed, sector_size - cbUsed);

    flash.deinit();
}



extern void RunMain();

int main()
{
    print_memory_info();
    // mbed_mem_trace_set_callback(mbed_mem_trace_default_callback);
    
    red = 1;
    blue = 1;
    green = 0;

    if (0 != net.connect()) {
        printf("Error connecting\n");
        return -1;
    }

    const char * ip = net.get_ip_address();
    printf("IP Address is %s\n", ip ? ip : "No IP");

    socket.open(&net);

    // dns_init();
    
    // UDPSocket::recvfrom is blocking, so run it in a separate RTOS thread
    recvfromThread.start(&recvfromMain);

    // queue = mbed_event_queue();
    myMainThread.start(RunMain);
}    
    
void RunMain()
{
    ReadFlash();
    UpdateFlash();

#if ACE_MBED_TLS
    MyTlsInit();
#endif

    //  Set things up for doing tokens
    randLIB_seed_random();

    //  Setup all of our coap protocol work

    // Initialize the CoAP protocol handle, pointing to local implementations on malloc/free/tx/rx functions
    coapHandle = sn_coap_protocol_init(&coap_malloc, &coap_free, &coap_tx_cb, &coap_rx_cb);

    //  Get message

    DoGetMessage();

    MyQueue.dispatch_forever();
    
    ThisThread::sleep_for(osWaitForever);
    //  sn_coap_protool_destroy(coapHandle); // Clean up
}


void DoOscoreGet()
{
   // Path to the resource we want to retrieve
    const char* coap_uri_path = "/oscore/hello/1"; // "/ace/helloWorld";

    // See ns_coap_header.h
    sn_coap_hdr_s *coap_res_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_res_ptr);
    
    coap_res_ptr->uri_path_ptr = (uint8_t*)coap_uri_path;       // Path
    coap_res_ptr->uri_path_len = strlen(coap_uri_path);
    coap_res_ptr->msg_code = COAP_MSG_CODE_REQUEST_GET;         // CoAP method
    
    // Message ID is used to track request->response patterns, because we're using UDP (so everything is unconfirmed).
    // See the receive code to verify that we get the same message ID back
    
    OscoreKey * useKey = FindOscoreKey((uint8_t *) "oscore", 6);
    OscoreMsgMatch * match = OscoreRequest(coap_res_ptr, useKey);

    if (!SendMessage(coap_res_ptr, match, DoOscoreGetResponse, RsAddress, RsPort)) {
        free(coap_res_ptr);
    }
}

void DoOscoreGetResponse(int index)
{
    blue = 0;
    red = 1;
    wait(0.2);
    
    sn_coap_hdr_s * coap_res_ptr = OscoreResponse(PendingMessages[index].sn_coap_response,
                                  (OscoreMsgMatch *) PendingMessages[index].callbackData);
    printf("\nOSCORE RESPONSE\n");
    printCoapMsg(coap_res_ptr);

    DispatchNext();
}


void DoAceGet()
{
    // Path to the resource we want to retrieve
    const char* coap_uri_path = "/ace/helloWorld"; //  "/ace/helloWorld";

    // See ns_coap_header.h
    sn_coap_hdr_s *coap_res_ptr = (sn_coap_hdr_s*)calloc(sizeof(sn_coap_hdr_s), 1);
    sn_coap_init_message(coap_res_ptr);

    coap_res_ptr->uri_path_ptr = (uint8_t*)coap_uri_path;       // Path
    coap_res_ptr->uri_path_len = strlen(coap_uri_path);
    coap_res_ptr->msg_code = COAP_MSG_CODE_REQUEST_GET;         // CoAP method

    if (!SendMessage(coap_res_ptr, NULL, DoAceGetResponse, RsAddress, RsPort)) {
        free(coap_res_ptr);
    }
}

void DoAceGetResponse(int index)
{
    printf("\nGET ACE RESPONSE\n");
    
    printCoapMsg(PendingMessages[index].sn_coap_response);

    if (PendingMessages[index].sn_coap_response->msg_code == COAP_MSG_CODE_RESPONSE_UNAUTHORIZED) {
        if (MakeAceRequest(&PendingMessages[index], "aud2", "read",
                           DoGetResponse, DoGetResponse, RsAddress, RsPort)) {
            return;
        }
    }
    DispatchNext();

    red = 0;
    blue = 1;
}

