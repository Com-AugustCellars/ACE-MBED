#include "mbed.h"

#include "mbedtls/net.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"

#include "mytls.h"

#if ACE_MBED_TLS

mbedtls_ssl_config TlsConfig;

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

static void my_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "mbed-tls: %s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}


int MyTlsSend(void * ctx, const unsigned char * buf, size_t len)
{
    MyTlsSession * myTlsSession = (MyTlsSession *) ctx;

    int scount = myTlsSession->socket.sendto(myTlsSession->addr_ptr, myTlsSession->port, buf, len);
    printf("Sent %d bytes to coap://%s:%d\n", scount, myTlsSession->addr_ptr, myTlsSession->port);
    return scount;
}

int MyTlsReceive(void * ctx, unsigned char * buf, size_t len)
{
    MyTlsSession * myTlsSession = (MyTlsSession *) ctx;
    SocketAddress addr;

    int ret = myTlsSession->socket.recvfrom(&addr, buf, len);
    if (ret < 0) {
        return ret; // ????
    }
    
    return ret;
}

int MyTlsReceiveTimeout(void * ctx, unsigned char * buf, size_t len, uint32_t timeout)
{
    MyTlsSession * myTlsSession = (MyTlsSession *) ctx;
    SocketAddress addr;

    myTlsSession->socket.set_timeout(timeout);
    
    int ret = myTlsSession->socket.recvfrom(&addr, buf, len);
    if (ret < 0) {
        if (ret == NSAPI_ERROR_WOULD_BLOCK) {
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
        return ret; // ????
    }
    
    return ret;
}


void recvFromTls(void * param)
{
    MyTlsSession * tlsSession = (MyTlsSession *) param;
    int ret;
    uint8_t * recv_buffer = (uint8_t *) malloc(1280);

    while (true) {
        ret = MyTlsRead(&tlsSession->tlsContext, recv_buffer, 1280);
        if (ret < 0) {
            if ((ret == MBEDTLS_ERR_SSL_WANT_READ) ||
                (ret == MBEDTLS_ERR_SSL_WANT_WRITE)) {
                // sleep and continue
                wait(0.1);
                continue;
            }
            else {
                //  This is fatal and should cause the entire session to be destroyed.
                return;
            }
        }
        
        //  Make the common code in recvfromMain be a subroutine

        if (ret > 0) {
            ProcessIncomingMessage(tlsSession->addr_ptr, tlsSession->port, recv_buffer, ret);
        }
    }
}


int MyTlsInit()
{
    const char * pers = "FooBar";
    int i;
    int ret;

    mbedtls_ssl_config_init(&TlsConfig);

    i = mbedtls_ssl_config_defaults(&TlsConfig, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
    if (i != 0) return i;

    mbedtls_ssl_conf_rng( &TlsConfig, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &TlsConfig, my_debug, stdout );

    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 ) {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        return ret;
    }    

    return 0;
}


int MyTlsRelease()
{
    // mbedtls_ssl_free(&TlsContext);
    return 0;
}

extern EthernetInterface net;

extern int my_mbedtls_timing_get_delay( void *data );
extern void my_mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms );


MyTlsSession * MyTlsOpenSession(const char * rsAddress, int rsPort, uint8_t * psk_id, int psk_id_len, uint8_t * psk, int psk_len)
{
    int ret;

    MyTlsSession * tlsSession = new MyTlsSession();
    if (tlsSession == NULL) {
        return NULL;
    }

    mbedtls_ssl_init(&tlsSession->tlsContext);

    ret = mbedtls_ssl_setup(&tlsSession->tlsContext, &TlsConfig);

    //  Open the socket
    tlsSession->socket.open(&net);
    tlsSession->addr_ptr = rsAddress;
    tlsSession->port = rsPort;
    
    mbedtls_ssl_set_bio(&tlsSession->tlsContext, tlsSession, MyTlsSend, MyTlsReceive, MyTlsReceiveTimeout);
    mbedtls_ssl_set_timer_cb( &tlsSession->tlsContext, &tlsSession->timer, my_mbedtls_timing_set_delay,
                              my_mbedtls_timing_get_delay );

    mbedtls_ssl_conf_psk(&TlsConfig, psk, psk_len, psk_id, psk_id_len);

    do {
        ret = mbedtls_ssl_handshake(&tlsSession->tlsContext);
    }
    while ( (ret == MBEDTLS_ERR_SSL_WANT_READ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE) );

    if (ret != 0) {
        return NULL;
    }
    
    mbedtls_ssl_conf_psk(&TlsConfig, NULL, 0, NULL, 0);

    //  Start the read thread

    tlsSession->thread.start(callback(&recvFromTls, tlsSession));

    return tlsSession;
}


//  Need to carry the COAP context data here as well.

int MyTlsWrite( mbedtls_ssl_context * ptlsContext, uint8_t * buffer, size_t len)
{

    return mbedtls_ssl_write(ptlsContext, buffer, len);
}

int MyTlsRead( mbedtls_ssl_context * ptlsContext, uint8_t * buffer, size_t len)
{
    int ret;
    
    do {
        ret = mbedtls_ssl_read(ptlsContext, buffer, len);
    }
    while (( ret == MBEDTLS_ERR_SSL_WANT_READ ) || (ret == MBEDTLS_ERR_SSL_WANT_WRITE));

    if (ret <= 0) {
        //  Do something here to recover some things

        return 0;
    }

    return ret;
}

int MyTlsClose( mbedtls_ssl_context * ptlsContext )
{
    int ret;
    do {
        ret = mbedtls_ssl_close_notify( ptlsContext );
    }
    while ( ret == MBEDTLS_ERR_SSL_WANT_WRITE );

    //  M00BUG: Need to close the reading thread.

    mbedtls_ssl_free( ptlsContext );

    return 0;
}
#endif // ACE_MBED_TLS
