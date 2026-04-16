/*
 * libFuzzer harness for the Signalforge dotenv parser.
 *
 * Target: sf_parser_parse() in ../src/parser.c
 *
 * Flow:
 *   - libFuzzer hands us (data, size)
 *   - we copy into a \0-terminated buffer (parser reads up to input_len,
 *     but defensively treats \0 as EOF in several states)
 *   - init ctx, parse, drain the result hashtable, free
 *
 * The input is raw bytes. The parser is expected to either succeed or
 * return -1 with error_msg set. Any crash, UAF, OOB, or ASan report is
 * a real finding.
 *
 * The parser normally runs under Zend's emalloc arena. We substitute a
 * malloc-backed shim (see ../../fuzz-support/php_stubs.h) so ASan gets
 * real byte-level precision on every allocation.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "../../fuzz-support/php_stubs.h"
#include "../src/parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Cap input size. The parser is linear but can allocate per-line;
     * a 1 MiB input that's all \n lines costs ~80 MB in bucket arrays,
     * which isn't interesting to fuzz. */
    if (size > 256 * 1024) return 0;

    /* Copy so ASan catches reads past end-of-buffer. */
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    if (size) memcpy(input, data, size);
    input[size] = '\0';

    sf_parser_ctx_t ctx;
    sf_parser_init(&ctx, input, size, NULL);

    (void)sf_parser_parse(&ctx);

    sf_parser_result_t result;
    sf_parser_get_result(&ctx, &result);

    /* Exercise the expansion pass with an empty env - still exercises
     * the ${VAR} scanner for memory safety. */
    if (result.values && !result.error) {
        smart_str out = {0};
        zend_string *k;
        zval *v;
        ZEND_HASH_FOREACH_STR_KEY_VAL(result.values, k, v) {
            if (k && v && Z_TYPE_P(v) == IS_STRING) {
                (void)sf_expand_variables(Z_STRVAL_P(v), Z_STRLEN_P(v),
                                          result.values, &out);
                smart_str_free(&out);
            }
        } ZEND_HASH_FOREACH_END();
    }

    sf_parser_result_free(&result);
    sf_parser_free(&ctx);

    free(input);
    return 0;
}
