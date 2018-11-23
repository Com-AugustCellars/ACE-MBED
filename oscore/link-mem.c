#include <stddef.h>
#include <stdlib.h>

#include "cn-cbor.h"

typedef struct {
    cn_cbor_context     cborctx;
    void **             ppv;
} MyContextObject;

void * LinkedCalloc(size_t count, size_t size, void * context)
{
    MyContextObject * ctx = (MyContextObject *) ((cn_cbor_context *) context)->context;
    void * ret = calloc(count*size+4, 1);
    *(void **) ret = (void *) ctx->ppv;
    ctx->ppv = ret;
    return (void *)(((uint8_t *) ret)+4);
}

void LinkedFree(void * ptr, void * context)
{
    return;
}

cn_cbor_context * CborAllocatorCreate()
{
    MyContextObject * ctx = (MyContextObject *) malloc(sizeof(MyContextObject));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->cborctx.calloc_func = LinkedCalloc;
    ctx->cborctx.free_func = LinkedFree;
    ctx->cborctx.context = ctx;
    ctx->ppv = NULL;

    return (cn_cbor_context *) ctx;
}

void CborAllocatorFree(cn_cbor_context * ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    MyContextObject * myctx = (MyContextObject *) ctx->context;

    void ** p = myctx->ppv;
    void ** p2;
    
    while (p != NULL) {
        p2 = (void **) *p;
        free(p);
        p = p2;
    }

    free(ctx);
}
