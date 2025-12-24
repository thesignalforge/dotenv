/*
 * Signalforge Dotenv Extension
 *
 * A PHP extension for loading, parsing, and decrypting .env files
 * with support for encrypted values using libsodium.
 *
 * Copyright (c) 2025 Signalforge
 * Licensed under the MIT License
 */

#ifndef PHP_SIGNALFORGE_DOTENV_H
#define PHP_SIGNALFORGE_DOTENV_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "zend_exceptions.h"
#include "zend_smart_str.h"

#include <sodium.h>

#define PHP_SIGNALFORGE_DOTENV_VERSION "1.0.0"
#define PHP_SIGNALFORGE_DOTENV_EXTNAME "signalforge_dotenv"

/* Forward declarations */
extern zend_module_entry signalforge_dotenv_module_entry;
#define phpext_signalforge_dotenv_ptr &signalforge_dotenv_module_entry

/* Exception class */
extern zend_class_entry *signalforge_dotenv_exception_ce;

/* Module globals - minimal, request-scoped where needed */
ZEND_BEGIN_MODULE_GLOBALS(signalforge_dotenv)
    /* Last error message for detailed diagnostics */
    char *last_error;
    size_t last_error_len;

    /* Cached parsed values for current request (optional optimization) */
    HashTable *cached_env;
    zend_bool cache_valid;
ZEND_END_MODULE_GLOBALS(signalforge_dotenv)

ZEND_EXTERN_MODULE_GLOBALS(signalforge_dotenv)

#define SIGNALFORGE_DOTENV_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(signalforge_dotenv, v)

/* Error codes */
typedef enum {
    SF_DOTENV_OK = 0,
    SF_DOTENV_ERR_FILE_NOT_FOUND,
    SF_DOTENV_ERR_FILE_READ,
    SF_DOTENV_ERR_PARSE,
    SF_DOTENV_ERR_DECRYPT,
    SF_DOTENV_ERR_KEY_REQUIRED,
    SF_DOTENV_ERR_KEY_INVALID,
    SF_DOTENV_ERR_MEMORY,
    SF_DOTENV_ERR_JSON_PARSE,
    SF_DOTENV_ERR_CRYPTO_INIT
} sf_dotenv_error_t;

/* Options structure parsed from PHP array */
typedef struct {
    zend_bool encrypted;        /* Whether to attempt decryption */
    zend_bool auto_detect;      /* Auto-detect encryption */
    zend_string *key;           /* Encryption key/passphrase */
    zend_string *key_env;       /* Env var name holding the key */
    zend_bool override;         /* Override existing env vars */
    zend_bool export_env;       /* Export to process environment */
    zend_bool export_server;    /* Export to $_SERVER */
    zend_string *format;        /* Value format: auto, plain, json */
    zend_bool parse_arrays;     /* Parse JSON arrays/objects */
} sf_dotenv_options_t;

/* Encryption header for versioned format */
#define SF_DOTENV_MAGIC "SFDOTENV"
#define SF_DOTENV_MAGIC_LEN 8
#define SF_DOTENV_VERSION_1 0x01

typedef struct {
    char magic[SF_DOTENV_MAGIC_LEN];
    uint8_t version;
    uint8_t reserved[3];
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
} sf_dotenv_header_t;

/* Function declarations */
PHP_MINIT_FUNCTION(signalforge_dotenv);
PHP_MSHUTDOWN_FUNCTION(signalforge_dotenv);
PHP_RINIT_FUNCTION(signalforge_dotenv);
PHP_RSHUTDOWN_FUNCTION(signalforge_dotenv);
PHP_MINFO_FUNCTION(signalforge_dotenv);

/* Main PHP function */
PHP_FUNCTION(dotenv);

/* Helper to set last error */
void sf_dotenv_set_error(const char *format, ...);

/* Clear sensitive memory */
void sf_dotenv_secure_zero(void *ptr, size_t len);

#endif /* PHP_SIGNALFORGE_DOTENV_H */
