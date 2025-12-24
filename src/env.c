/*
 * Signalforge Dotenv Extension - Environment Injection
 *
 * Handles injection of parsed values into PHP environment:
 * - getenv() / putenv()
 * - $_ENV superglobal
 * - $_SERVER superglobal
 */

#include "env.h"
#include "php.h"
#include "ext/json/php_json.h"
#include "ext/standard/php_string.h"
#include "SAPI.h"
#include <stdlib.h>
#include <string.h>

/* Track putenv allocations to prevent leaks */
typedef struct {
    char **entries;
    size_t count;
    size_t capacity;
} sf_putenv_tracker_t;

static sf_putenv_tracker_t putenv_tracker = {NULL, 0, 0};

/* Register a putenv string for cleanup */
static void track_putenv_entry(char *entry)
{
    if (putenv_tracker.count >= putenv_tracker.capacity) {
        size_t new_capacity = putenv_tracker.capacity == 0 ? 16 : putenv_tracker.capacity * 2;
        char **new_entries = erealloc(putenv_tracker.entries, new_capacity * sizeof(char *));
        if (!new_entries) {
            return;
        }
        putenv_tracker.entries = new_entries;
        putenv_tracker.capacity = new_capacity;
    }
    putenv_tracker.entries[putenv_tracker.count++] = entry;
}

/* Clean up tracked putenv entries (called on RSHUTDOWN) */
void sf_env_cleanup_putenv(void)
{
    for (size_t i = 0; i < putenv_tracker.count; i++) {
        if (putenv_tracker.entries[i]) {
            /* Note: We cannot safely unsetenv here as other code may hold pointers.
             * The entries will be freed when the process exits.
             * For FPM/Swoole, we accept this minor leak per-request. */
            efree(putenv_tracker.entries[i]);
        }
    }
    if (putenv_tracker.entries) {
        efree(putenv_tracker.entries);
    }
    putenv_tracker.entries = NULL;
    putenv_tracker.count = 0;
    putenv_tracker.capacity = 0;
}

bool sf_env_validate_key(const char *key, size_t key_len)
{
    if (key_len == 0) {
        return false;
    }

    /* First character must be letter or underscore */
    char c = key[0];
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')) {
        return false;
    }

    /* Remaining characters can include digits */
    for (size_t i = 1; i < key_len; i++) {
        c = key[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }

    return true;
}

zend_string *sf_env_serialize_value(zval *value)
{
    switch (Z_TYPE_P(value)) {
        case IS_STRING:
            return zend_string_copy(Z_STR_P(value));

        case IS_LONG:
            return zend_long_to_str(Z_LVAL_P(value));

        case IS_DOUBLE: {
            char buf[64];
            int len = snprintf(buf, sizeof(buf), "%.*G", (int)EG(precision), Z_DVAL_P(value));
            return zend_string_init(buf, len, 0);
        }

        case IS_TRUE:
            return zend_string_init("true", 4, 0);

        case IS_FALSE:
            return zend_string_init("false", 5, 0);

        case IS_NULL:
            return zend_string_init("", 0, 0);

        case IS_ARRAY: {
            /* JSON encode arrays */
            smart_str buf = {0};
            php_json_encode(&buf, value, PHP_JSON_UNESCAPED_SLASHES | PHP_JSON_UNESCAPED_UNICODE);
            smart_str_0(&buf);
            zend_string *result = buf.s ? zend_string_copy(buf.s) : zend_string_init("[]", 2, 0);
            smart_str_free(&buf);
            return result;
        }

        default:
            /* For other types, convert to string if possible */
            if (Z_TYPE_P(value) == IS_OBJECT) {
                zval str_val;
                if (zend_std_cast_object_tostring(Z_OBJ_P(value), &str_val, IS_STRING) == SUCCESS) {
                    zend_string *result = zend_string_copy(Z_STR(str_val));
                    zval_ptr_dtor(&str_val);
                    return result;
                }
            }
            return zend_string_init("", 0, 0);
    }
}

sf_env_error_t sf_env_set(
    const char *key,
    size_t key_len,
    const char *value,
    size_t value_len,
    sf_env_target_t targets,
    bool override)
{
    zend_string *zkey;
    zend_string *zvalue;

    if (!sf_env_validate_key(key, key_len)) {
        return SF_ENV_ERR_INVALID_KEY;
    }

    zkey = zend_string_init(key, key_len, 0);
    zvalue = zend_string_init(value, value_len, 0);

    /* Check if we should skip (no override and exists) */
    if (!override && sf_env_exists(key, key_len)) {
        zend_string_release(zkey);
        zend_string_release(zvalue);
        return SF_ENV_OK;
    }

    /* Inject into $_ENV */
    if (targets & SF_ENV_TARGET_ENV) {
        zval *env_arr = &PG(http_globals)[TRACK_VARS_ENV];
        if (Z_TYPE_P(env_arr) == IS_ARRAY) {
            zval zv;
            ZVAL_STR_COPY(&zv, zvalue);
            zend_hash_update(Z_ARRVAL_P(env_arr), zkey, &zv);
        }
    }

    /* Inject into $_SERVER */
    if (targets & SF_ENV_TARGET_SERVER) {
        zval *server_arr = &PG(http_globals)[TRACK_VARS_SERVER];
        if (Z_TYPE_P(server_arr) == IS_ARRAY) {
            zval zv;
            ZVAL_STR_COPY(&zv, zvalue);
            zend_hash_update(Z_ARRVAL_P(server_arr), zkey, &zv);
        }
    }

    /* Inject into process environment via putenv */
    if (targets & SF_ENV_TARGET_GETENV) {
        /* Format: KEY=VALUE\0 */
        size_t env_len = key_len + 1 + value_len + 1;
        char *env_str = emalloc(env_len);
        if (!env_str) {
            zend_string_release(zkey);
            zend_string_release(zvalue);
            return SF_ENV_ERR_MEMORY;
        }

        memcpy(env_str, key, key_len);
        env_str[key_len] = '=';
        memcpy(env_str + key_len + 1, value, value_len);
        env_str[env_len - 1] = '\0';

        if (putenv(env_str) != 0) {
            efree(env_str);
            zend_string_release(zkey);
            zend_string_release(zvalue);
            return SF_ENV_ERR_PUTENV;
        }

        /* Track for cleanup */
        track_putenv_entry(env_str);
    }

    zend_string_release(zkey);
    zend_string_release(zvalue);
    return SF_ENV_OK;
}

sf_env_error_t sf_env_set_zval(
    const char *key,
    size_t key_len,
    zval *value,
    sf_env_target_t targets,
    bool override)
{
    zend_string *zkey;
    zend_string *serialized;

    if (!sf_env_validate_key(key, key_len)) {
        return SF_ENV_ERR_INVALID_KEY;
    }

    if (!override && sf_env_exists(key, key_len)) {
        return SF_ENV_OK;
    }

    zkey = zend_string_init(key, key_len, 0);

    /* For $_ENV and $_SERVER, we can store arrays directly */
    if ((targets & SF_ENV_TARGET_ENV) || (targets & SF_ENV_TARGET_SERVER)) {
        if (targets & SF_ENV_TARGET_ENV) {
            zval *env_arr = &PG(http_globals)[TRACK_VARS_ENV];
            if (Z_TYPE_P(env_arr) == IS_ARRAY) {
                zval copy;
                ZVAL_COPY(&copy, value);
                zend_hash_update(Z_ARRVAL_P(env_arr), zkey, &copy);
            }
        }

        if (targets & SF_ENV_TARGET_SERVER) {
            zval *server_arr = &PG(http_globals)[TRACK_VARS_SERVER];
            if (Z_TYPE_P(server_arr) == IS_ARRAY) {
                zval copy;
                ZVAL_COPY(&copy, value);
                zend_hash_update(Z_ARRVAL_P(server_arr), zkey, &copy);
            }
        }
    }

    /* For getenv, we need to serialize to string */
    if (targets & SF_ENV_TARGET_GETENV) {
        serialized = sf_env_serialize_value(value);
        if (!serialized) {
            zend_string_release(zkey);
            return SF_ENV_ERR_MEMORY;
        }

        size_t env_len = key_len + 1 + ZSTR_LEN(serialized) + 1;
        char *env_str = emalloc(env_len);
        if (!env_str) {
            zend_string_release(serialized);
            zend_string_release(zkey);
            return SF_ENV_ERR_MEMORY;
        }

        memcpy(env_str, key, key_len);
        env_str[key_len] = '=';
        memcpy(env_str + key_len + 1, ZSTR_VAL(serialized), ZSTR_LEN(serialized));
        env_str[env_len - 1] = '\0';

        zend_string_release(serialized);

        if (putenv(env_str) != 0) {
            efree(env_str);
            zend_string_release(zkey);
            return SF_ENV_ERR_PUTENV;
        }

        track_putenv_entry(env_str);
    }

    zend_string_release(zkey);
    return SF_ENV_OK;
}

size_t sf_env_set_all(
    HashTable *values,
    sf_env_target_t targets,
    bool override)
{
    size_t count = 0;
    zend_string *key;
    zval *value;

    ZEND_HASH_FOREACH_STR_KEY_VAL(values, key, value) {
        if (key) {
            sf_env_error_t err = sf_env_set_zval(
                ZSTR_VAL(key),
                ZSTR_LEN(key),
                value,
                targets,
                override
            );
            if (err == SF_ENV_OK) {
                count++;
            }
        }
    } ZEND_HASH_FOREACH_END();

    return count;
}

bool sf_env_exists(const char *key, size_t key_len)
{
    zend_string *zkey = zend_string_init(key, key_len, 0);

    /* Check $_ENV */
    zval *env_arr = &PG(http_globals)[TRACK_VARS_ENV];
    if (Z_TYPE_P(env_arr) == IS_ARRAY) {
        if (zend_hash_exists(Z_ARRVAL_P(env_arr), zkey)) {
            zend_string_release(zkey);
            return true;
        }
    }

    /* Check getenv */
    char *env_key = estrndup(key, key_len);
    char *env_val = getenv(env_key);
    efree(env_key);

    zend_string_release(zkey);
    return env_val != NULL;
}

zend_string *sf_env_get(const char *key, size_t key_len)
{
    zend_string *zkey = zend_string_init(key, key_len, 0);

    /* Check $_ENV first */
    zval *env_arr = &PG(http_globals)[TRACK_VARS_ENV];
    if (Z_TYPE_P(env_arr) == IS_ARRAY) {
        zval *val = zend_hash_find(Z_ARRVAL_P(env_arr), zkey);
        if (val && Z_TYPE_P(val) == IS_STRING) {
            zend_string_release(zkey);
            return zend_string_copy(Z_STR_P(val));
        }
    }

    zend_string_release(zkey);

    /* Fall back to getenv */
    char *env_key = estrndup(key, key_len);
    char *env_val = getenv(env_key);
    efree(env_key);

    if (env_val) {
        return zend_string_init(env_val, strlen(env_val), 0);
    }

    return NULL;
}

HashTable *sf_env_get_all(void)
{
    HashTable *result;
    extern char **environ;

    ALLOC_HASHTABLE(result);
    zend_hash_init(result, 64, NULL, ZVAL_PTR_DTOR, 0);

    /* Start with process environment */
    if (environ) {
        for (char **env = environ; *env; env++) {
            char *eq = strchr(*env, '=');
            if (eq) {
                size_t key_len = eq - *env;
                zend_string *key = zend_string_init(*env, key_len, 0);
                zval val;
                ZVAL_STRING(&val, eq + 1);
                zend_hash_update(result, key, &val);
                zend_string_release(key);
            }
        }
    }

    /* Override with $_ENV */
    zval *env_arr = &PG(http_globals)[TRACK_VARS_ENV];
    if (Z_TYPE_P(env_arr) == IS_ARRAY) {
        zend_string *key;
        zval *value;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(env_arr), key, value) {
            if (key) {
                zval copy;
                ZVAL_COPY(&copy, value);
                zend_hash_update(result, key, &copy);
            }
        } ZEND_HASH_FOREACH_END();
    }

    return result;
}
