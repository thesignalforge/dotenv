/*
 * Signalforge Dotenv Extension - Parser Implementation
 *
 * Single-pass state machine parser for .env files.
 */

#include "parser.h"
#include "php.h"
#include "ext/json/php_json.h"
#include "zend_smart_str.h"
#include <ctype.h>
#include <string.h>

/* Character classification helpers */
static inline bool is_key_start_char(char c)
{
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_';
}

static inline bool is_key_char(char c)
{
    return is_key_start_char(c) ||
           (c >= '0' && c <= '9');
}

static inline bool is_whitespace(char c)
{
    return c == ' ' || c == '\t';
}

static inline bool is_newline(char c)
{
    return c == '\n' || c == '\r';
}

/* Parser helper: peek at current character */
static inline char parser_peek(sf_parser_ctx_t *ctx)
{
    if (ctx->pos >= ctx->input_len) {
        return '\0';
    }
    return ctx->input[ctx->pos];
}

/* Parser helper: advance to next character */
static inline void parser_advance(sf_parser_ctx_t *ctx)
{
    if (ctx->pos < ctx->input_len) {
        char c = ctx->input[ctx->pos];
        ctx->pos++;
        if (c == '\n') {
            ctx->line++;
            ctx->column = 1;
        } else {
            ctx->column++;
        }
    }
}

/* Parser helper: consume and return current character */
static inline char parser_consume(sf_parser_ctx_t *ctx)
{
    char c = parser_peek(ctx);
    parser_advance(ctx);
    return c;
}

/* Set parser error */
static void parser_set_error(sf_parser_ctx_t *ctx, const char *msg)
{
    if (ctx->error_msg) {
        efree(ctx->error_msg);
    }
    ctx->error_msg = estrdup(msg);
    ctx->error_line = ctx->line;
    ctx->error_column = ctx->column;
}

/* Process escape sequence in double-quoted strings */
static char process_escape(sf_parser_ctx_t *ctx)
{
    char c = parser_consume(ctx);
    switch (c) {
        case 'n': return '\n';
        case 'r': return '\r';
        case 't': return '\t';
        case '\\': return '\\';
        case '"': return '"';
        case '\'': return '\'';
        case '$': return '$';
        case '`': return '`';
        default:
            /* Unknown escape, keep as-is */
            return c;
    }
}

/* Store current key-value pair */
static void parser_store_value(sf_parser_ctx_t *ctx)
{
    if (ctx->current_key.s == NULL || ZSTR_LEN(ctx->current_key.s) == 0) {
        return;
    }

    smart_str_0(&ctx->current_key);
    smart_str_0(&ctx->current_value);

    zend_string *key = ctx->current_key.s;
    zend_string *value = ctx->current_value.s ? ctx->current_value.s : ZSTR_EMPTY_ALLOC();

    zval zv;
    ZVAL_STR_COPY(&zv, value);

    zend_hash_update(ctx->result, key, &zv);

    /* Clear for next pair */
    smart_str_free(&ctx->current_key);
    smart_str_free(&ctx->current_value);
    memset(&ctx->current_key, 0, sizeof(smart_str));
    memset(&ctx->current_value, 0, sizeof(smart_str));
}

void sf_parser_init(
    sf_parser_ctx_t *ctx,
    const char *input,
    size_t input_len,
    HashTable *existing_env)
{
    memset(ctx, 0, sizeof(sf_parser_ctx_t));

    ctx->input = input;
    ctx->input_len = input_len;
    ctx->pos = 0;
    ctx->line = 1;
    ctx->column = 1;
    ctx->state = PARSER_STATE_LINE_START;
    ctx->expand_variables = true;
    ctx->parse_json = true;
    ctx->existing_env = existing_env;

    ALLOC_HASHTABLE(ctx->result);
    zend_hash_init(ctx->result, 32, NULL, ZVAL_PTR_DTOR, 0);
}

void sf_parser_set_options(
    sf_parser_ctx_t *ctx,
    bool expand_variables,
    bool parse_json)
{
    ctx->expand_variables = expand_variables;
    ctx->parse_json = parse_json;
}

int sf_parser_parse(sf_parser_ctx_t *ctx)
{
    while (ctx->pos < ctx->input_len) {
        char c = parser_peek(ctx);

        switch (ctx->state) {
            case PARSER_STATE_LINE_START:
                if (is_whitespace(c)) {
                    parser_advance(ctx);
                } else if (c == '#') {
                    ctx->state = PARSER_STATE_COMMENT;
                    parser_advance(ctx);
                } else if (is_newline(c)) {
                    parser_advance(ctx);
                } else if (is_key_start_char(c)) {
                    ctx->state = PARSER_STATE_KEY;
                    smart_str_appendc(&ctx->current_key, c);
                    parser_advance(ctx);
                } else {
                    parser_set_error(ctx, "Invalid character at start of line");
                    return -1;
                }
                break;

            case PARSER_STATE_KEY:
                if (is_key_char(c)) {
                    smart_str_appendc(&ctx->current_key, c);
                    parser_advance(ctx);
                } else if (c == '=' || is_whitespace(c)) {
                    ctx->state = PARSER_STATE_AFTER_KEY;
                } else if (is_newline(c)) {
                    /* Key without value */
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_START;
                    parser_advance(ctx);
                } else {
                    parser_set_error(ctx, "Invalid character in key name");
                    return -1;
                }
                break;

            case PARSER_STATE_AFTER_KEY:
                if (is_whitespace(c)) {
                    parser_advance(ctx);
                } else if (c == '=') {
                    ctx->state = PARSER_STATE_BEFORE_VALUE;
                    parser_advance(ctx);
                } else {
                    parser_set_error(ctx, "Expected '=' after key");
                    return -1;
                }
                break;

            case PARSER_STATE_BEFORE_VALUE:
                if (is_whitespace(c)) {
                    parser_advance(ctx);
                } else if (c == '"') {
                    ctx->state = PARSER_STATE_VALUE_DOUBLE_QUOTED;
                    ctx->quote_char = '"';
                    parser_advance(ctx);
                } else if (c == '\'') {
                    ctx->state = PARSER_STATE_VALUE_SINGLE_QUOTED;
                    ctx->quote_char = '\'';
                    parser_advance(ctx);
                } else if (c == '`') {
                    ctx->state = PARSER_STATE_VALUE_BACKTICK;
                    ctx->quote_char = '`';
                    parser_advance(ctx);
                } else if (is_newline(c) || c == '\0') {
                    /* Empty value */
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_START;
                    if (c != '\0') parser_advance(ctx);
                } else if (c == '#') {
                    /* Empty value with comment */
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_COMMENT;
                    parser_advance(ctx);
                } else {
                    ctx->state = PARSER_STATE_VALUE_UNQUOTED;
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_VALUE_UNQUOTED:
                if (is_newline(c) || c == '\0') {
                    /* Trim trailing whitespace from unquoted value */
                    if (ctx->current_value.s) {
                        char *end = ZSTR_VAL(ctx->current_value.s) + ZSTR_LEN(ctx->current_value.s) - 1;
                        while (end >= ZSTR_VAL(ctx->current_value.s) && is_whitespace(*end)) {
                            end--;
                            ZSTR_LEN(ctx->current_value.s)--;
                        }
                    }
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_START;
                    if (c != '\0') parser_advance(ctx);
                } else if (c == '#') {
                    /* Check for inline comment (preceded by whitespace) */
                    if (ctx->current_value.s && ZSTR_LEN(ctx->current_value.s) > 0) {
                        char *end = ZSTR_VAL(ctx->current_value.s) + ZSTR_LEN(ctx->current_value.s) - 1;
                        if (is_whitespace(*end)) {
                            /* Trim trailing whitespace and treat as comment */
                            while (end >= ZSTR_VAL(ctx->current_value.s) && is_whitespace(*end)) {
                                end--;
                                ZSTR_LEN(ctx->current_value.s)--;
                            }
                            parser_store_value(ctx);
                            ctx->state = PARSER_STATE_COMMENT;
                            parser_advance(ctx);
                            break;
                        }
                    }
                    /* # not preceded by whitespace, part of value */
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                } else {
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_VALUE_SINGLE_QUOTED:
                if (c == '\'') {
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_END;
                    parser_advance(ctx);
                } else if (c == '\\') {
                    /* Check for escaped quote */
                    if (ctx->pos + 1 < ctx->input_len && ctx->input[ctx->pos + 1] == '\'') {
                        parser_advance(ctx);
                        smart_str_appendc(&ctx->current_value, '\'');
                        parser_advance(ctx);
                    } else {
                        smart_str_appendc(&ctx->current_value, c);
                        parser_advance(ctx);
                    }
                } else if (c == '\0') {
                    parser_set_error(ctx, "Unterminated single-quoted string");
                    return -1;
                } else {
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_VALUE_DOUBLE_QUOTED:
                if (c == '"') {
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_END;
                    parser_advance(ctx);
                } else if (c == '\\') {
                    parser_advance(ctx);
                    if (ctx->pos < ctx->input_len) {
                        char escaped = process_escape(ctx);
                        smart_str_appendc(&ctx->current_value, escaped);
                    }
                } else if (c == '\0') {
                    parser_set_error(ctx, "Unterminated double-quoted string");
                    return -1;
                } else {
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_VALUE_BACKTICK:
                if (c == '`') {
                    parser_store_value(ctx);
                    ctx->state = PARSER_STATE_LINE_END;
                    parser_advance(ctx);
                } else if (c == '\\') {
                    parser_advance(ctx);
                    if (ctx->pos < ctx->input_len) {
                        char escaped = process_escape(ctx);
                        smart_str_appendc(&ctx->current_value, escaped);
                    }
                } else if (c == '\0') {
                    parser_set_error(ctx, "Unterminated backtick string");
                    return -1;
                } else {
                    smart_str_appendc(&ctx->current_value, c);
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_COMMENT:
                if (is_newline(c)) {
                    ctx->state = PARSER_STATE_LINE_START;
                    parser_advance(ctx);
                } else {
                    parser_advance(ctx);
                }
                break;

            case PARSER_STATE_LINE_END:
                if (is_whitespace(c)) {
                    parser_advance(ctx);
                } else if (c == '#') {
                    ctx->state = PARSER_STATE_COMMENT;
                    parser_advance(ctx);
                } else if (is_newline(c) || c == '\0') {
                    ctx->state = PARSER_STATE_LINE_START;
                    if (c != '\0') parser_advance(ctx);
                } else {
                    parser_set_error(ctx, "Unexpected character after quoted value");
                    return -1;
                }
                break;

            default:
                parser_set_error(ctx, "Internal parser error: invalid state");
                return -1;
        }
    }

    /* Handle end of input */
    switch (ctx->state) {
        case PARSER_STATE_KEY:
        case PARSER_STATE_VALUE_UNQUOTED:
        case PARSER_STATE_BEFORE_VALUE:
        case PARSER_STATE_AFTER_KEY:
            parser_store_value(ctx);
            break;
        case PARSER_STATE_VALUE_SINGLE_QUOTED:
        case PARSER_STATE_VALUE_DOUBLE_QUOTED:
        case PARSER_STATE_VALUE_BACKTICK:
            parser_set_error(ctx, "Unterminated quoted string at end of file");
            return -1;
        default:
            break;
    }

    return 0;
}

void sf_parser_get_result(sf_parser_ctx_t *ctx, sf_parser_result_t *result)
{
    result->values = ctx->result;
    result->error = ctx->error_msg;
    result->error_line = ctx->error_line;
    result->error_column = ctx->error_column;

    /* Transfer ownership */
    ctx->result = NULL;
    ctx->error_msg = NULL;
}

void sf_parser_free(sf_parser_ctx_t *ctx)
{
    smart_str_free(&ctx->current_key);
    smart_str_free(&ctx->current_value);

    if (ctx->error_msg) {
        efree(ctx->error_msg);
        ctx->error_msg = NULL;
    }

    if (ctx->result) {
        zend_hash_destroy(ctx->result);
        FREE_HASHTABLE(ctx->result);
        ctx->result = NULL;
    }
}

void sf_parser_result_free(sf_parser_result_t *result)
{
    if (result->values) {
        zend_hash_destroy(result->values);
        FREE_HASHTABLE(result->values);
        result->values = NULL;
    }
    if (result->error) {
        efree(result->error);
        result->error = NULL;
    }
}

/* Variable expansion implementation */
int sf_expand_variables(
    const char *input,
    size_t input_len,
    HashTable *env,
    smart_str *output)
{
    size_t i = 0;

    while (i < input_len) {
        if (input[i] == '$' && i + 1 < input_len) {
            bool has_braces = (input[i + 1] == '{');
            size_t start, end;
            char *default_value = NULL;
            size_t default_len = 0;
            bool use_default_if_empty = false;
            bool use_alternate = false;

            if (has_braces) {
                start = i + 2;
                end = start;

                /* Find closing brace */
                while (end < input_len && input[end] != '}') {
                    end++;
                }

                if (end >= input_len) {
                    /* No closing brace, copy literally */
                    smart_str_appendc(output, '$');
                    i++;
                    continue;
                }

                /* Check for default/alternate value syntax */
                size_t var_end = start;
                while (var_end < end) {
                    if (input[var_end] == ':' && var_end + 1 < end) {
                        if (input[var_end + 1] == '-') {
                            use_default_if_empty = true;
                            default_value = (char *)&input[var_end + 2];
                            default_len = end - (var_end + 2);
                            break;
                        } else if (input[var_end + 1] == '+') {
                            use_alternate = true;
                            default_value = (char *)&input[var_end + 2];
                            default_len = end - (var_end + 2);
                            break;
                        }
                    } else if (input[var_end] == '-' && !use_default_if_empty) {
                        default_value = (char *)&input[var_end + 1];
                        default_len = end - (var_end + 1);
                        break;
                    }
                    var_end++;
                }

                size_t key_len = (default_value ? (var_end - start) : (end - start));
                zend_string *key = zend_string_init(&input[start], key_len, 0);
                zval *val = zend_hash_find(env, key);

                if (use_alternate) {
                    /* ${VAR:+alternate} - use alternate if VAR is set and non-empty */
                    if (val && Z_TYPE_P(val) == IS_STRING && Z_STRLEN_P(val) > 0) {
                        smart_str_appendl(output, default_value, default_len);
                    }
                } else if (val && Z_TYPE_P(val) == IS_STRING) {
                    if (use_default_if_empty && Z_STRLEN_P(val) == 0 && default_value) {
                        smart_str_appendl(output, default_value, default_len);
                    } else {
                        smart_str_append(output, Z_STR_P(val));
                    }
                } else if (default_value) {
                    smart_str_appendl(output, default_value, default_len);
                }
                /* If no value and no default, expand to empty string */

                zend_string_release(key);
                i = end + 1;
            } else {
                /* $VAR without braces */
                start = i + 1;
                end = start;

                while (end < input_len && is_key_char(input[end])) {
                    end++;
                }

                if (end == start) {
                    /* Just a $ sign */
                    smart_str_appendc(output, '$');
                    i++;
                    continue;
                }

                zend_string *key = zend_string_init(&input[start], end - start, 0);
                zval *val = zend_hash_find(env, key);

                if (val && Z_TYPE_P(val) == IS_STRING) {
                    smart_str_append(output, Z_STR_P(val));
                }

                zend_string_release(key);
                i = end;
            }
        } else {
            smart_str_appendc(output, input[i]);
            i++;
        }
    }

    smart_str_0(output);
    return 0;
}

bool sf_looks_like_json(const char *value, size_t value_len)
{
    if (value_len < 2) {
        return false;
    }

    /* Skip leading whitespace */
    size_t start = 0;
    while (start < value_len && is_whitespace(value[start])) {
        start++;
    }

    if (start >= value_len) {
        return false;
    }

    /* Check for array or object start */
    return value[start] == '[' || value[start] == '{';
}

bool sf_try_parse_json(
    const char *value,
    size_t value_len,
    zval *result)
{
    if (!sf_looks_like_json(value, value_len)) {
        return false;
    }

    /* Use PHP's JSON parser */
    zend_string *json_str = zend_string_init(value, value_len, 0);

    php_json_decode_ex(
        result,
        ZSTR_VAL(json_str),
        ZSTR_LEN(json_str),
        PHP_JSON_OBJECT_AS_ARRAY,
        512
    );

    zend_string_release(json_str);

    if (Z_TYPE_P(result) == IS_ARRAY) {
        return true;
    }

    /* Failed to parse, clear any partial result */
    zval_ptr_dtor(result);
    ZVAL_UNDEF(result);
    return false;
}
