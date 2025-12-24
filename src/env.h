/*
 * Signalforge Dotenv Extension - Environment Injection
 *
 * Functions for injecting parsed values into:
 * - getenv() / putenv()
 * - $_ENV superglobal
 * - $_SERVER superglobal
 */

#ifndef SF_DOTENV_ENV_H
#define SF_DOTENV_ENV_H

#include "php.h"
#include <stdbool.h>

/* Injection targets */
typedef enum {
    SF_ENV_TARGET_NONE    = 0,
    SF_ENV_TARGET_GETENV  = (1 << 0),   /* putenv() */
    SF_ENV_TARGET_ENV     = (1 << 1),   /* $_ENV */
    SF_ENV_TARGET_SERVER  = (1 << 2),   /* $_SERVER */
    SF_ENV_TARGET_ALL     = SF_ENV_TARGET_GETENV | SF_ENV_TARGET_ENV | SF_ENV_TARGET_SERVER
} sf_env_target_t;

/* Result codes */
typedef enum {
    SF_ENV_OK = 0,
    SF_ENV_ERR_MEMORY,
    SF_ENV_ERR_PUTENV,
    SF_ENV_ERR_INVALID_KEY
} sf_env_error_t;

/**
 * Inject a single key-value pair into environment
 *
 * @param key Variable name
 * @param key_len Length of key
 * @param value Variable value
 * @param value_len Length of value
 * @param targets Bitmask of injection targets
 * @param override Whether to override existing values
 * @return SF_ENV_OK on success, error code otherwise
 */
sf_env_error_t sf_env_set(
    const char *key,
    size_t key_len,
    const char *value,
    size_t value_len,
    sf_env_target_t targets,
    bool override
);

/**
 * Inject a zval value into environment
 *
 * If the value is an array, it will be JSON-encoded for process environment.
 *
 * @param key Variable name
 * @param key_len Length of key
 * @param value Value zval
 * @param targets Bitmask of injection targets
 * @param override Whether to override existing values
 * @return SF_ENV_OK on success, error code otherwise
 */
sf_env_error_t sf_env_set_zval(
    const char *key,
    size_t key_len,
    zval *value,
    sf_env_target_t targets,
    bool override
);

/**
 * Inject all values from a hashtable
 *
 * @param values Hashtable of key => value pairs
 * @param targets Bitmask of injection targets
 * @param override Whether to override existing values
 * @return Number of values successfully injected
 */
size_t sf_env_set_all(
    HashTable *values,
    sf_env_target_t targets,
    bool override
);

/**
 * Check if an environment variable exists
 *
 * Checks all sources: getenv(), $_ENV, $_SERVER
 *
 * @param key Variable name
 * @param key_len Length of key
 * @return true if variable exists
 */
bool sf_env_exists(const char *key, size_t key_len);

/**
 * Get an environment variable value
 *
 * Looks up in order: $_ENV, getenv()
 *
 * @param key Variable name
 * @param key_len Length of key
 * @return zend_string* or NULL if not found (caller must release)
 */
zend_string *sf_env_get(const char *key, size_t key_len);

/**
 * Get current environment as a hashtable
 *
 * Merges $_ENV and getenv() results.
 *
 * @return New hashtable (caller must release)
 */
HashTable *sf_env_get_all(void);

/**
 * Validate environment variable name
 *
 * Must match: [a-zA-Z_][a-zA-Z0-9_]*
 *
 * @param key Variable name
 * @param key_len Length of key
 * @return true if valid
 */
bool sf_env_validate_key(const char *key, size_t key_len);

/**
 * Serialize a zval to string for environment storage
 *
 * Arrays/objects are JSON encoded, other types converted to string.
 *
 * @param value Input zval
 * @return zend_string* (caller must release) or NULL on error
 */
zend_string *sf_env_serialize_value(zval *value);

#endif /* SF_DOTENV_ENV_H */
