#ifndef __MYTLS_H__
#define __MYTLS_H__

#if ACE_MBED_TLS

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#include "EthernetInterface.h"


typedef struct {
    mbedtls_ssl_context tlsContext;
    Thread              recvFromThread;
    UDPSocket           socket;
    const char *        addr_ptr;
    uint16_t            port;
    Thread              thread;
    mbedtls_timing_delay_context timer;
} MyTlsSession;

extern int MyTlsInit();

extern MyTlsSession * MyTlsOpenSession(const char * rsAddress, int rsPort, uint8_t * psk, int psk_len, uint8_t * psk_id, int psk_id_len);
extern int MyTlsWrite( mbedtls_ssl_context * ptlsContext, uint8_t * buffer, size_t len);
extern int MyTlsRead( mbedtls_ssl_context * ptlsContext, uint8_t * buffer, size_t len);

extern void ProcessIncomingMessage(const char * address, uint16_t port, uint8_t * recv_buffer, nsapi_size_or_error_t ret);


#endif // ACE_EMBED_TLS
#endif // __MYTLS_H__
