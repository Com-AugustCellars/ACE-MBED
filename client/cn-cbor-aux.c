#include <stddef.h>

#include "cn-cbor.h"
#include "cn-cbor-aux.h"

#if 0
cn_cbor * cn_cbor_array_replace(cn_cbor * cb_array, int index, cn_cbor * cb_value, cn_cbor_errback * errp)
{
    cn_cbor * returnVal;
    // Make sure the input is an array.
    if (!cb_array || !cb_value || cb_array->type!= CN_CBOR_ARRAY) {
        if (errp) {
            errp->err = CN_CBOR_ERR_INVALID_PARAMETER;
        }
        return NULL;
    }

    if (index == 0) {
        //  Replace the first child
        returnVal = cb_array->first_child;
        cb_value->next = returnVal->next;
        returnVal->next = NULL;
        cb_array->first_child = cb_value;
    }
    else {
        cn_cbor * tmp = cb_array->first_child;
        while (index != 1) {
            tmp = tmp->next;
            index--;
            if (tmp == NULL) {
                errp->err = CN_CBOR_ERR_INVALID_PARAMETER;
            }
            return NULL;
        }
        returnVal = tmp->next;
        tmp->next = cb_value;
        cb_value->next = returnVal->next;
        returnVal->next = NULL;
    }

    return returnVal;
}
#endif
