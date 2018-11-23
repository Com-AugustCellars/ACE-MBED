#include <string>
#include <stddef.h>
#include <mbed.h>
#include <sn_coap_protocol.h>
#include <sn_coap_header.h>

#include "cn-cbor.h"
#include "oscore.h"
#include "cose.h"
#include "hkdf.h"
#include "mbedtls/sha256.h"
#include "cn-cbor-aux.h"
#include "link-mem.h"

 //   COSE_Algorithm_AES_CCM_16_64_128 = 10,
 
#define COAP_MSG_CODE_REQUEST_FETCH (sn_coap_msg_code_e) 5


extern coap_s * coapHandle;
extern coap_version_e coapVersion;


void WriteToFlash(cn_cbor * cborData)
{
    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    // const uint32_t sector_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    int page_size = flash.get_page_size();
    
    int cb = cn_cbor_encoder_write(NULL, 0, 0, cborData);
    
    //  Assert cb+4 < page_size
    int cbAlloc = ((cb + page_size) & ~(page_size-1)) + 4;
    uint8_t * rgb = (uint8_t *) calloc(cbAlloc, 1);
    cn_cbor_encoder_write(rgb, 4, cbAlloc, cborData);
    *(uint32_t *) rgb = cb;
    
    printf("Starting\n");
    flash.erase(address, flash.get_sector_size(address));

    flash.program(rgb, address, cbAlloc);
    
    flash.deinit();
    
    free(rgb);
}

/*  STRUCTURE

destination - IP Addr + port OR Name + port
Algorithm - fixed to 10
KDF - fixed to HKDF
Secret -  BSTR
Salt - BSTR | NIL

Sender ID
Next PIV Saved

Recipient ID
Next Replay window Start

*/

OscoreKey * DeriveOscoreContext(const cn_cbor * input)
{
    uint8_t rgb[128];
    cn_cbor_context * ctx = CborAllocatorCreate();

    OscoreKey * keyOut = (OscoreKey *) calloc(sizeof(OscoreKey), 1);
    cn_cbor * cborInfo = cn_cbor_array_create(ctx, NULL);
    cn_cbor * cborKey = cn_cbor_mapget_int(input, -1);
    
    cn_cbor * tmp = cn_cbor_mapget_int(input, 6);       // Client ID
	
    cn_cbor_array_append(cborInfo, cn_cbor_data_create(tmp->v.bytes, tmp->length, ctx, NULL), NULL); // ID
    keyOut->senderID_ptr = (byte *) malloc(tmp->length);
    keyOut->senderID_len = tmp->length;
    memcpy(keyOut->senderID_ptr, tmp->v.bytes, tmp->length);

    cn_cbor * cb_salt = cn_cbor_mapget_int(input, 9);      // Salt
    const uint8_t * salt = NULL;
    int cbSalt = 0;
    if (cb_salt != NULL) {
        salt = cb_salt->v.bytes;
        cbSalt = cb_salt->length;
    }

        
    cn_cbor_array_append(cborInfo, cn_cbor_null_create(ctx, NULL), NULL);  // id_context

    keyOut->algorithm = 10;
    cn_cbor_array_append(cborInfo, cn_cbor_int_create(10, ctx, NULL), NULL); // algorithm

    cn_cbor_array_append(cborInfo, cn_cbor_string_create("Key", ctx, NULL), NULL);

    cn_cbor_array_append(cborInfo, cn_cbor_int_create(128/8, ctx, NULL), NULL);

    int cb = cn_cbor_encoder_write(rgb, 0, sizeof(rgb), cborInfo);

    uint8_t * key = (uint8_t *) malloc(128/8);

    const mbedtls_md_info_t * x = mbedtls_md_info_from_string("SHA256");

    
    mbedtls_hkdf(x, salt, cbSalt, cborKey->v.bytes, cborKey->length, rgb, cb, key, 128/8);

    keyOut->key_ptr = key;
    keyOut->key_len = 128/8;

    tmp = cn_cbor_mapget_int(input, 7);       // Server ID
    keyOut->recipID_ptr = (byte *) malloc(tmp->length);
    keyOut->recipID_len = tmp->length;
    memcpy(keyOut->recipID_ptr, tmp->v.bytes, tmp->length);
    cn_cbor_array_replace(cborInfo, cn_cbor_data_create(tmp->v.bytes, tmp->length, ctx, NULL), 0, ctx, NULL); // ID

    key = (uint8_t *) malloc(128/8);
    
    cb = cn_cbor_encoder_write(rgb, 0, sizeof(rgb), cborInfo);
    mbedtls_hkdf(x, salt, cbSalt, cborKey->v.bytes, cborKey->length, rgb, cb, key, 128/8);

    keyOut->recipKey_ptr = key;
    keyOut->recipKey_len = 128/8;
    
    cn_cbor_array_replace(cborInfo, cn_cbor_data_create(NULL, 0, ctx, NULL), 0, ctx, NULL); // ID
    cn_cbor_array_replace(cborInfo, cn_cbor_string_create("IV", ctx, NULL), 3, ctx, NULL);
    cn_cbor_array_replace(cborInfo, cn_cbor_int_create(13, ctx, NULL), 4, ctx, NULL);

    cb = cn_cbor_encoder_write(rgb, 0, sizeof(rgb), cborInfo);
    
    uint8_t * iv = (uint8_t *) malloc(13);
    mbedtls_hkdf(x, salt, cbSalt, cborKey->v.bytes, cborKey->length, rgb, cb, iv, 13);

    keyOut->baseIV_ptr = iv;
    keyOut->baseIV_len = 13;

    tmp = cn_cbor_mapget_int(input, 2);      // Key Identifier
    if (tmp != NULL) {
        keyOut->kid_ptr = (uint8_t *) malloc(tmp->length);
        memcpy(keyOut->kid_ptr, tmp->v.bytes, tmp->length);
        keyOut->kid_len = tmp->length;
    }

    CborAllocatorFree(ctx);
    
    return keyOut;
}


void SaveToFlash()
{
    cn_cbor_context * ctx = CborAllocatorCreate();
    cn_cbor * cbor = cn_cbor_array_create(ctx, NULL);
    
    OscoreKey * p = AllOscoreKeys;
    for (; p != NULL; p = p->next) {
        if (!p->save) {
            continue;
        }
        
        cn_cbor * cborKey = cn_cbor_array_create(ctx, NULL);
        cn_cbor * t;
        
        t = cn_cbor_data_create(p->kid_ptr, p->kid_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);
        
        t = cn_cbor_data_create(p->key_ptr, p->key_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);
        
        t = cn_cbor_int_create(p->algorithm, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);
        
        t = cn_cbor_data_create(p->baseIV_ptr, p->baseIV_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);
        
        t = cn_cbor_data_create(p->senderID_ptr, p->senderID_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);

        t = cn_cbor_data_create(p->recipID_ptr, p->recipID_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);

        t = cn_cbor_data_create(p->recipKey_ptr, p->recipKey_len, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);

        t = cn_cbor_int_create((p->partialIV + 2*64) & ~63, ctx, NULL);
        cn_cbor_array_append(cborKey, t, NULL);
        printf("-- Flash updated keys PIV = %x and saved = %x\n", p->partialIV, t->v.uint);
        
        cn_cbor_array_append(cbor, cborKey, NULL);
    }
    
    WriteToFlash(cbor);
    
    CborAllocatorFree(ctx);
}

///     WriteKeysToBuffer
//
//  Write all of the keys to a buffer,
//  if buffer is NULL then just compute size
//
//  buffer - write to buffer if not NULL
//  cb - size of the buffer
//
//  Return count of bytes written

int WriteKeysToBuffer(uint8_t * buffer, int cb)
{
    int  ib = 0;
    int cKeys = 0;
    
    //  Write number of keys out
    
    ib += 1;

    OscoreKey * p = AllOscoreKeys;
    for (; p != NULL; p = p->next) {
        if (!p->save) {
            continue;
        }

        cKeys += 1;

        //  Write out the KID

        if (buffer != NULL) {
            if (ib + p->kid_len + 1 > cb) {
                return -1;
            }
            buffer[ib] = p->kid_len;
            memcpy(buffer+ib+1, p->kid_ptr, p->kid_len);
        }
        ib += 1 + p->kid_len;

        //  Write out the actual Key
        
        if (buffer != NULL) {
            buffer[ib] = p->key_len;
            memcpy(buffer+ib+1, p->key_ptr, p->key_len);
        }
        ib += 1 + p->key_len;

        //  Write out the base IV

        if (buffer != NULL) {
            buffer[ib] = p->baseIV_len;
            memcpy(buffer+ib+1, p->baseIV_ptr, p->baseIV_len);
        }
        ib += 1 + p->baseIV_len;

        //  Write out the sender ID
        
        if (buffer != NULL) {
            buffer[ib] = p->senderID_len;
            memcpy(buffer+ib+1, p->senderID_ptr, p->senderID_len);
        }
        ib += 1 + p->senderID_len;

        //  Write out the recipient ID
        
        if (buffer != NULL) {
            buffer[ib] = p->recipID_len;
            memcpy(buffer+ib+1, p->recipID_ptr, p->recipID_len);
        }
        ib += 1 + p->recipID_len;

        //  Write out the recipient Key

        if (buffer != NULL) {
            buffer[ib] = p->recipKey_len;
            memcpy(buffer+ib+1, p->recipKey_ptr, p->recipKey_len);
        }
        ib += 1 + p->recipKey_len;

        //  Write out the Parital IV

        if (buffer != NULL) {
            *(uint32_t *)(buffer+ib) = (p->partialIV + 2*64) & ~63;
        }
        ib += 4;

        //  Write out the algorithm - assume its only one byte

        if (buffer != NULL) {
            buffer[ib] = p->algorithm;
        }
        ib += 1;
    }

    //  Really write out the number of keys
    
    if (buffer != NULL) {
        buffer[0] = cKeys;
    }

    return ib;
    
}

#define READ_DATA(data_ptr, data_len) \
    { \
        if ( ib + 1 > length) return -1; \
        byte cb = buffer[ib++]; \
        if (ib + cb > length) return -1; \
        uint8_t * pb = (uint8_t *) malloc(cb); \
        if (pb == NULL) return -1; \
        memcpy(pb, buffer+ib, cb); \
        ib += cb; \
        data_ptr = pb;          \
        data_len = cb; \
    }
        

///  ReadKeysFromBuffer
//

int ReadKeysFromBuffer(uint8_t * buffer, int length)
{
    int ib = 0;
    int cKeys;

    //  Read # of keys
    if (ib + 1 > length) {
        return -1;
    }
    cKeys = buffer[ib];
    ib += 1;

    //  Read each key out

    for (int iKey=0; iKey <cKeys; iKey++) {
        OscoreKey * key = (OscoreKey *) calloc(sizeof(OscoreKey), 1);
        if (key == NULL) {
            return -1;
        }

        //  Get the KID

        READ_DATA(key->kid_ptr, key->kid_len);

        //  Write out the key

        READ_DATA(key->key_ptr, key->key_len)

        //  Get the base IV

        READ_DATA(key->baseIV_ptr, key->baseIV_len);

        //  Get the sender ID

        READ_DATA(key->senderID_ptr, key->senderID_len);

        //  Get the recipient ID

        READ_DATA(key->recipID_ptr, key->recipID_len);

        //  Get the recipient key

        READ_DATA(key->recipKey_ptr, key->recipKey_len);

        //  Get the partial IV

        if (ib + 5 > length) return -1;
        key->partialIV = *(uint32_t *) &buffer[ib];
        ib += 4;

        key->algorithm = buffer[ib];
        ib += 1;

        key->save = true;
        key->next = AllOscoreKeys;
        AllOscoreKeys = key;
    }

    return ib;
}

#if 0
    
bool RestoreFromFlash(uint32_t address)
{
    int cb = *(int *) address;
    
    cn_cbor * cborKeys = cn_cbor_decode(((const uint8_t *) address)+4, cb, NULL, NULL);
    cn_cbor * cbor;
    for (cbor = cborKeys->first_child; cbor != NULL; cbor = cbor->next) {
        OscoreKey * p = (OscoreKey *) malloc(sizeof(OscoreKey));

        cn_cbor * cbor2 = cn_cbor_index(cbor, 0);
        uint8_t * pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->kid_ptr = pb;
        p->kid_len = cbor2->length;

        cbor2 = cn_cbor_index(cbor, 1);
        pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->key_ptr = pb;
        p->key_len = cbor2->length;

        cbor2 = cn_cbor_index(cbor, 2);
        p->algorithm = cbor2->v.sint;
        
        cbor2 = cn_cbor_index(cbor, 3);
        pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->baseIV_ptr = pb;
        p->baseIV_len = cbor2->length;
        
        cbor2 = cn_cbor_index(cbor, 4);
        pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->senderID_ptr = pb;
        p->senderID_len = cbor2->length;
        
        cbor2 = cn_cbor_index(cbor, 5);
        pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->recipID_ptr = pb;
        p->recipID_len = cbor2->length;
        
        cbor2 = cn_cbor_index(cbor, 6);
        pb = (uint8_t *) malloc(cbor2->length);
        memcpy(pb, cbor2->v.bytes, cbor2->length);
        p->recipKey_ptr = pb;
        p->recipKey_len = cbor2->length;
        
        cbor2 = cn_cbor_index(cbor, 7);
        p->partialIV = cbor2->v.sint;
        
        p->save = true;
        
        p->next = AllOscoreKeys;
        AllOscoreKeys = p;
    }
    
    cn_cbor_free(cborKeys, NULL);
    
    return true;
}


void KeySetup()
{
    FlashIAP flash;

    flash.init();
    
    uint32_t address = flash.get_flash_start() + flash.get_flash_size();
    const uint32_t page_size = flash.get_sector_size(address-1);
    address = address - flash.get_sector_size(address-1);   
    
    flash.deinit();

    if (*((int *) address) == -1) {
        //// HALT !!!!
    }
    else {
        uint8_t * buffer = (uint8_t *) address;
        int length = pag_size;
        ReadKeysFromBuffer(buffer, length);
        
        SaveToFlash();
    }
}
#endif
    
