#include <cn-cbor.h>

#ifndef __OSCORE_H__
#define __OSCORE_H__

#ifdef  __cplusplus
extern "C" {
#endif
#ifdef EMACS_INDENTATION_HELPER
} /* Duh. */
#endif

typedef uint8_t byte;

typedef struct oscoreKey {
	  struct oscoreKey * next;
	  int    save;
    byte * kid_ptr;
    int    kid_len;
    byte * key_ptr;
    int    key_len;
    int    algorithm;
    byte * baseIV_ptr;
    int    baseIV_len;
    byte * senderID_ptr;
    int    senderID_len;
    byte * recipID_ptr;
    int    recipID_len;
    byte * recipKey_ptr;
    int    recipKey_len;
    uint32_t partialIV;
} OscoreKey;

typedef struct {
    byte   partialIV[4];        // Network order!!!
    int    partialIV_len;
    OscoreKey * key_ptr;
} OscoreMsgMatch;

OscoreMsgMatch * OscoreRequest(sn_coap_hdr_s *, OscoreKey *);
sn_coap_hdr_s * OscoreResponse(sn_coap_hdr_s *, OscoreMsgMatch *);

sn_coap_hdr_s * sn_coap_init_message(sn_coap_hdr_s * coap_msg_ptr);
sn_coap_options_list_s * sn_coap_init_options_list(sn_coap_options_list_s * coap_options_ptr);


extern OscoreKey * AllOscoreKeys;
extern void KeySetup();
extern void SaveToFlash();
extern OscoreKey * DeriveOscoreContext(const cn_cbor * input);

extern OscoreKey * FindOscoreKey(const uint8_t * id, int length);
extern int WriteKeysToBuffer(uint8_t * buffer, int length);
extern int ReadKeysFromBuffer(uint8_t * buffer, int length);

#ifdef __cplusplus
}
#endif


#endif // __OSCORE_H__
