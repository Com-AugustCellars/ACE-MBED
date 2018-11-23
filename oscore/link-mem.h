/***  CN_CBOR context allocator
 */

#ifndef __link_mem_h__
#define __link_mem_h__

#include <cn-cbor.h>

#ifdef  __cplusplus
extern "C" {
#endif
#ifdef EMACS_INDENTATION_HELPER
} /* Duh. */
#endif


extern cn_cbor_context * CborAllocatorCreate();
extern void CborAllocatorFree(cn_cbor_context * ctx);

#ifdef  __cplusplus
}
#endif

#endif /* __link_mem_h__ */
