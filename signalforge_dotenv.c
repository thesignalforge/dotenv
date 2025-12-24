/*
 * Signalforge Dotenv Extension
 *
 * Main extension file: module registration, PHP function implementation
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_signalforge_dotenv.h"
#include "src/parser.h"
#include "src/crypto.h"
#include "src/env.h"

#include "ext/standard/file.h"
#include "ext/standard/flock_compat.h"
#include "zend_smart_str.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* Module globals */
ZEND_DECLARE_MODULE_GLOBALS(signalforge_dotenv)

/* Exception class entry */
zend_class_entry *signalforge_dotenv_exception_ce;

/* Forward declaration for cleanup */
extern void sf_env_cleanup_putenv(void);

/* Helper: set last error message */
void sf_dotenv_set_error(const char *format, ...)
{
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (SIGNALFORGE_DOTENV_G(last_error)) {
        efree(SIGNALFORGE_DOTENV_G(last_error));
    }

    SIGNALFORGE_DOTENV_G(last_error) = estrdup(buffer);
    SIGNALFORGE_DOTENV_G(last_error_len) = strlen(buffer);
}

/* Helper: secure memory zeroing */
void sf_dotenv_secure_zero(void *ptr, size_t len)
{
    sf_crypto_secure_zero(ptr, len);
}

/* Parse options array from PHP */
static void parse_options(zval *options_zv, sf_dotenv_options_t *opts)
{
    HashTable *options;
    zval *val;

    /* Set defaults */
    memset(opts, 0, sizeof(sf_dotenv_options_t));
    opts->auto_detect = true;
    opts->export_env = true;
    opts->parse_arrays = true;

    if (options_zv == NULL || Z_TYPE_P(options_zv) != IS_ARRAY) {
        return;
    }

    options = Z_ARRVAL_P(options_zv);

    /* encrypted: bool */
    val = zend_hash_str_find(options, "encrypted", sizeof("encrypted") - 1);
    if (val) {
        opts->encrypted = zend_is_true(val);
        opts->auto_detect = false;  /* Explicit setting disables auto-detect */
    }

    /* key: string */
    val = zend_hash_str_find(options, "key", sizeof("key") - 1);
    if (val && Z_TYPE_P(val) == IS_STRING) {
        opts->key = Z_STR_P(val);
    }

    /* key_env: string */
    val = zend_hash_str_find(options, "key_env", sizeof("key_env") - 1);
    if (val && Z_TYPE_P(val) == IS_STRING) {
        opts->key_env = Z_STR_P(val);
    }

    /* override: bool */
    val = zend_hash_str_find(options, "override", sizeof("override") - 1);
    if (val) {
        opts->override = zend_is_true(val);
    }

    /* export: bool */
    val = zend_hash_str_find(options, "export", sizeof("export") - 1);
    if (val) {
        opts->export_env = zend_is_true(val);
    }

    /* export_server: bool */
    val = zend_hash_str_find(options, "export_server", sizeof("export_server") - 1);
    if (val) {
        opts->export_server = zend_is_true(val);
    }

    /* format: string */
    val = zend_hash_str_find(options, "format", sizeof("format") - 1);
    if (val && Z_TYPE_P(val) == IS_STRING) {
        opts->format = Z_STR_P(val);
    }

    /* arrays: bool */
    val = zend_hash_str_find(options, "arrays", sizeof("arrays") - 1);
    if (val) {
        opts->parse_arrays = zend_is_true(val);
    }
}

/* Read file contents */
static unsigned char *read_file(const char *path, size_t *len)
{
    struct stat st;
    int fd;
    unsigned char *content;
    ssize_t bytes_read;

    if (stat(path, &st) != 0) {
        return NULL;
    }

    if (!S_ISREG(st.st_mode)) {
        return NULL;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    content = emalloc(st.st_size + 1);
    if (!content) {
        close(fd);
        return NULL;
    }

    bytes_read = read(fd, content, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        efree(content);
        return NULL;
    }

    content[st.st_size] = '\0';
    *len = st.st_size;
    return content;
}

/* Get encryption key from options or environment */
static zend_string *get_encryption_key(sf_dotenv_options_t *opts)
{
    /* Direct key takes precedence */
    if (opts->key) {
        return zend_string_copy(opts->key);
    }

    /* Try environment variable */
    if (opts->key_env) {
        zend_string *key = sf_env_get(ZSTR_VAL(opts->key_env), ZSTR_LEN(opts->key_env));
        if (key) {
            return key;
        }
    }

    /* Try default SIGNALFORGE_DOTENV_KEY */
    zend_string *key = sf_env_get("SIGNALFORGE_DOTENV_KEY", sizeof("SIGNALFORGE_DOTENV_KEY") - 1);
    if (key) {
        return key;
    }

    /* Try DOTENV_PRIVATE_KEY for dotenvx compatibility */
    key = sf_env_get("DOTENV_PRIVATE_KEY", sizeof("DOTENV_PRIVATE_KEY") - 1);
    return key;
}

/* Post-process parsed values: variable expansion and JSON parsing */
static void post_process_values(HashTable *values, sf_dotenv_options_t *opts)
{
    zend_string *key;
    zval *value;
    HashTable *expanded;

    /* Build environment for expansion (existing + parsed) */
    HashTable *env = sf_env_get_all();

    /* Add parsed values to env for self-referential expansion */
    ZEND_HASH_FOREACH_STR_KEY_VAL(values, key, value) {
        if (key && Z_TYPE_P(value) == IS_STRING) {
            zval copy;
            ZVAL_COPY(&copy, value);
            zend_hash_update(env, key, &copy);
        }
    } ZEND_HASH_FOREACH_END();

    /* Expand variables and parse JSON */
    ALLOC_HASHTABLE(expanded);
    zend_hash_init(expanded, zend_hash_num_elements(values), NULL, ZVAL_PTR_DTOR, 0);

    ZEND_HASH_FOREACH_STR_KEY_VAL(values, key, value) {
        if (!key || Z_TYPE_P(value) != IS_STRING) {
            continue;
        }

        smart_str expanded_val = {0};
        sf_expand_variables(
            Z_STRVAL_P(value),
            Z_STRLEN_P(value),
            env,
            &expanded_val
        );
        smart_str_0(&expanded_val);

        /* Try JSON parsing if enabled */
        if (opts->parse_arrays && expanded_val.s) {
            zval json_val;
            if (sf_try_parse_json(ZSTR_VAL(expanded_val.s), ZSTR_LEN(expanded_val.s), &json_val)) {
                zend_hash_update(expanded, key, &json_val);
                smart_str_free(&expanded_val);
                continue;
            }
        }

        /* Store as string */
        zval str_val;
        if (expanded_val.s) {
            ZVAL_STR(&str_val, expanded_val.s);
        } else {
            ZVAL_EMPTY_STRING(&str_val);
        }
        zend_hash_update(expanded, key, &str_val);
    } ZEND_HASH_FOREACH_END();

    /* Replace original values with expanded */
    zend_hash_clean(values);
    ZEND_HASH_FOREACH_STR_KEY_VAL(expanded, key, value) {
        if (key) {
            zval copy;
            ZVAL_COPY(&copy, value);
            zend_hash_update(values, key, &copy);
        }
    } ZEND_HASH_FOREACH_END();

    zend_hash_destroy(expanded);
    FREE_HASHTABLE(expanded);
    zend_hash_destroy(env);
    FREE_HASHTABLE(env);
}

/* {{{ proto array Signalforge\dotenv(string $path = ".env", array $options = [])
   Load and parse a .env file */
PHP_FUNCTION(dotenv)
{
    char *path = ".env";
    size_t path_len = sizeof(".env") - 1;
    zval *options_zv = NULL;
    sf_dotenv_options_t opts;
    unsigned char *content = NULL;
    size_t content_len = 0;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    sf_parser_ctx_t parser;
    sf_parser_result_t result;
    sf_env_target_t targets;

    ZEND_PARSE_PARAMETERS_START(0, 2)
        Z_PARAM_OPTIONAL
        Z_PARAM_STRING(path, path_len)
        Z_PARAM_ARRAY(options_zv)
    ZEND_PARSE_PARAMETERS_END();

    /* Parse options */
    parse_options(options_zv, &opts);

    /* Read file */
    content = read_file(path, &content_len);
    if (!content) {
        zend_throw_exception_ex(
            signalforge_dotenv_exception_ce,
            SF_DOTENV_ERR_FILE_NOT_FOUND,
            "Failed to read file: %s",
            path
        );
        RETURN_THROWS();
    }

    /* Check for encryption and decrypt if needed */
    bool is_encrypted = sf_crypto_is_encrypted(content, content_len);

    if (is_encrypted || (opts.encrypted && !opts.auto_detect)) {
        zend_string *key = get_encryption_key(&opts);
        if (!key) {
            efree(content);
            zend_throw_exception_ex(
                signalforge_dotenv_exception_ce,
                SF_DOTENV_ERR_KEY_REQUIRED,
                "Encryption key required but not provided"
            );
            RETURN_THROWS();
        }

        /* Allocate plaintext buffer */
        plaintext_len = sf_crypto_plaintext_max_len(content_len);
        plaintext = emalloc(plaintext_len + 1);
        if (!plaintext) {
            zend_string_release(key);
            efree(content);
            zend_throw_exception_ex(
                signalforge_dotenv_exception_ce,
                SF_DOTENV_ERR_MEMORY,
                "Memory allocation failed"
            );
            RETURN_THROWS();
        }

        /* Decrypt */
        sf_crypto_error_t crypto_err = sf_crypto_decrypt(
            content,
            content_len,
            (unsigned char *)ZSTR_VAL(key),
            ZSTR_LEN(key),
            plaintext,
            &plaintext_len,
            plaintext_len
        );

        /* Secure cleanup of key */
        sf_crypto_secure_zero(ZSTR_VAL(key), ZSTR_LEN(key));
        zend_string_release(key);

        if (crypto_err != SF_CRYPTO_OK) {
            sf_crypto_secure_zero(plaintext, plaintext_len);
            efree(plaintext);
            efree(content);
            zend_throw_exception_ex(
                signalforge_dotenv_exception_ce,
                SF_DOTENV_ERR_DECRYPT,
                "Decryption failed: %s",
                sf_crypto_error_str(crypto_err)
            );
            RETURN_THROWS();
        }

        plaintext[plaintext_len] = '\0';

        /* Use decrypted content */
        efree(content);
        content = plaintext;
        content_len = plaintext_len;
        plaintext = NULL;  /* Ownership transferred */
    }

    /* Parse .env content */
    sf_parser_init(&parser, (char *)content, content_len, NULL);
    sf_parser_set_options(&parser, true, opts.parse_arrays);

    if (sf_parser_parse(&parser) != 0) {
        sf_parser_get_result(&parser, &result);
        sf_parser_free(&parser);

        /* Secure cleanup */
        sf_crypto_secure_zero(content, content_len);
        efree(content);

        zend_throw_exception_ex(
            signalforge_dotenv_exception_ce,
            SF_DOTENV_ERR_PARSE,
            "Parse error at line %zu, column %zu: %s",
            result.error_line,
            result.error_column,
            result.error ? result.error : "Unknown error"
        );
        sf_parser_result_free(&result);
        RETURN_THROWS();
    }

    sf_parser_get_result(&parser, &result);
    sf_parser_free(&parser);

    /* Secure cleanup of file content */
    sf_crypto_secure_zero(content, content_len);
    efree(content);

    /* Post-process: variable expansion and JSON parsing */
    post_process_values(result.values, &opts);

    /* Inject into environment */
    if (opts.export_env) {
        targets = SF_ENV_TARGET_GETENV | SF_ENV_TARGET_ENV;
        if (opts.export_server) {
            targets |= SF_ENV_TARGET_SERVER;
        }
        sf_env_set_all(result.values, targets, opts.override);
    }

    /* Return parsed values */
    RETVAL_ARR(result.values);

    /* Don't free result.values as it's being returned */
    if (result.error) {
        efree(result.error);
    }
}
/* }}} */

/* Arginfo for dotenv function */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_signalforge_dotenv, 0, 0, IS_ARRAY, 0)
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, path, IS_STRING, 0, "\".env\"")
    ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, options, IS_ARRAY, 0, "[]")
ZEND_END_ARG_INFO()

/* Function entries */
static const zend_function_entry signalforge_dotenv_functions[] = {
    ZEND_NS_FE("Signalforge", dotenv, arginfo_signalforge_dotenv)
    PHP_FE_END
};

/* Module init */
PHP_MINIT_FUNCTION(signalforge_dotenv)
{
    zend_class_entry ce;

    /* Register exception class */
    INIT_NS_CLASS_ENTRY(ce, "Signalforge", "DotenvException", NULL);
    signalforge_dotenv_exception_ce = zend_register_internal_class_ex(&ce, zend_ce_exception);

    /* Initialize crypto subsystem */
    if (sf_crypto_init() != SF_CRYPTO_OK) {
        php_error_docref(NULL, E_WARNING, "Failed to initialize cryptography subsystem");
        /* Continue anyway - encryption just won't work */
    }

    return SUCCESS;
}

/* Module shutdown */
PHP_MSHUTDOWN_FUNCTION(signalforge_dotenv)
{
    return SUCCESS;
}

/* Request init */
PHP_RINIT_FUNCTION(signalforge_dotenv)
{
#if defined(ZTS) && defined(COMPILE_DL_SIGNALFORGE_DOTENV)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    SIGNALFORGE_DOTENV_G(last_error) = NULL;
    SIGNALFORGE_DOTENV_G(last_error_len) = 0;
    SIGNALFORGE_DOTENV_G(cached_env) = NULL;
    SIGNALFORGE_DOTENV_G(cache_valid) = 0;

    return SUCCESS;
}

/* Request shutdown */
PHP_RSHUTDOWN_FUNCTION(signalforge_dotenv)
{
    if (SIGNALFORGE_DOTENV_G(last_error)) {
        efree(SIGNALFORGE_DOTENV_G(last_error));
        SIGNALFORGE_DOTENV_G(last_error) = NULL;
    }

    if (SIGNALFORGE_DOTENV_G(cached_env)) {
        zend_hash_destroy(SIGNALFORGE_DOTENV_G(cached_env));
        FREE_HASHTABLE(SIGNALFORGE_DOTENV_G(cached_env));
        SIGNALFORGE_DOTENV_G(cached_env) = NULL;
    }

    sf_env_cleanup_putenv();

    return SUCCESS;
}

/* Module info */
PHP_MINFO_FUNCTION(signalforge_dotenv)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "signalforge_dotenv support", "enabled");
    php_info_print_table_row(2, "Version", PHP_SIGNALFORGE_DOTENV_VERSION);
    php_info_print_table_row(2, "Encryption", "libsodium (Argon2id + XSalsa20-Poly1305)");
    php_info_print_table_end();
}

/* Globals initialization */
static PHP_GINIT_FUNCTION(signalforge_dotenv)
{
#if defined(COMPILE_DL_SIGNALFORGE_DOTENV) && defined(ZTS)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    signalforge_dotenv_globals->last_error = NULL;
    signalforge_dotenv_globals->last_error_len = 0;
    signalforge_dotenv_globals->cached_env = NULL;
    signalforge_dotenv_globals->cache_valid = 0;
}

/* Module entry */
zend_module_entry signalforge_dotenv_module_entry = {
    STANDARD_MODULE_HEADER,
    PHP_SIGNALFORGE_DOTENV_EXTNAME,
    signalforge_dotenv_functions,
    PHP_MINIT(signalforge_dotenv),
    PHP_MSHUTDOWN(signalforge_dotenv),
    PHP_RINIT(signalforge_dotenv),
    PHP_RSHUTDOWN(signalforge_dotenv),
    PHP_MINFO(signalforge_dotenv),
    PHP_SIGNALFORGE_DOTENV_VERSION,
    PHP_MODULE_GLOBALS(signalforge_dotenv),
    PHP_GINIT(signalforge_dotenv),
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_SIGNALFORGE_DOTENV
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(signalforge_dotenv)
#endif
