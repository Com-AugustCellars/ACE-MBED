#ifdef  __cplusplus
extern "C" {
#endif
#ifdef EMACS_INDENTATION_HELPER
} /* Duh. */
#endif

/**
 * Replace an item in a cbor array and return the old item
 *
 * @param[in]   cb_array        The array in which the replacement is done
 * @param[in]   index           Which element to replace
 * @param[in]   cb_value        The value to replace with
 * @param[out]  errp            Error
 * @return                      The old value
 */

extern bool /*cn_cbor * */ cn_cbor_array_replace(cn_cbor * cb_array, cn_cbor * cb_value, int index, CBOR_CONTEXT_COMMA cn_cbor_errback * errp);

#ifdef  __cplusplus
}
#endif
