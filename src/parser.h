/*
 * Signalforge Dotenv Extension - Parser
 *
 * Single-pass .env file parser supporting:
 * - Standard KEY=value format
 * - Quoted values (single, double)
 * - Multiline values
 * - Comments
 * - Variable expansion
 * - JSON value parsing
 */

#ifndef SF_DOTENV_PARSER_H
#define SF_DOTENV_PARSER_H

#include "php.h"
#include "zend_smart_str.h"
#include <stdbool.h>

/* Parser state machine states */
typedef enum {
    PARSER_STATE_LINE_START,
    PARSER_STATE_KEY,
    PARSER_STATE_AFTER_KEY,
    PARSER_STATE_BEFORE_VALUE,
    PARSER_STATE_VALUE_UNQUOTED,
    PARSER_STATE_VALUE_SINGLE_QUOTED,
    PARSER_STATE_VALUE_DOUBLE_QUOTED,
    PARSER_STATE_VALUE_BACKTICK,
    PARSER_STATE_ESCAPE,
    PARSER_STATE_COMMENT,
    PARSER_STATE_LINE_END
} sf_parser_state_t;

/* Parser context */
typedef struct {
    const char *input;
    size_t input_len;
    size_t pos;
    size_t line;
    size_t column;

    /* Current token being built */
    smart_str current_key;
    smart_str current_value;

    /* State machine */
    sf_parser_state_t state;
    sf_parser_state_t saved_state;  /* For escape sequences */
    char quote_char;

    /* Options */
    bool expand_variables;
    bool parse_json;

    /* Result hashtable */
    HashTable *result;

    /* Existing environment for variable expansion */
    HashTable *existing_env;

    /* Error state */
    char *error_msg;
    size_t error_line;
    size_t error_column;
} sf_parser_ctx_t;

/* Parser result */
typedef struct {
    HashTable *values;      /* Parsed key-value pairs */
    char *error;            /* Error message or NULL */
    size_t error_line;      /* Line number of error */
    size_t error_column;    /* Column of error */
} sf_parser_result_t;

/**
 * Initialize parser context
 *
 * @param ctx Parser context to initialize
 * @param input Input string to parse
 * @param input_len Length of input
 * @param existing_env Existing environment for variable expansion (can be NULL)
 */
void sf_parser_init(
    sf_parser_ctx_t *ctx,
    const char *input,
    size_t input_len,
    HashTable *existing_env
);

/**
 * Configure parser options
 *
 * @param ctx Parser context
 * @param expand_variables Whether to expand ${VAR} references
 * @param parse_json Whether to parse JSON values
 */
void sf_parser_set_options(
    sf_parser_ctx_t *ctx,
    bool expand_variables,
    bool parse_json
);

/**
 * Parse the input
 *
 * @param ctx Parser context
 * @return 0 on success, -1 on error
 */
int sf_parser_parse(sf_parser_ctx_t *ctx);

/**
 * Get parse result
 *
 * @param ctx Parser context
 * @param result Output result structure
 */
void sf_parser_get_result(sf_parser_ctx_t *ctx, sf_parser_result_t *result);

/**
 * Free parser context resources
 *
 * @param ctx Parser context
 */
void sf_parser_free(sf_parser_ctx_t *ctx);

/**
 * Free parser result resources
 *
 * @param result Parser result
 */
void sf_parser_result_free(sf_parser_result_t *result);

/**
 * Expand variables in a string
 *
 * @param input Input string
 * @param input_len Length of input
 * @param env Environment hashtable for lookups
 * @param output Output smart string
 * @return 0 on success, -1 on error
 */
int sf_expand_variables(
    const char *input,
    size_t input_len,
    HashTable *env,
    smart_str *output
);

/**
 * Try to parse a value as JSON
 *
 * @param value Value string
 * @param value_len Length of value
 * @param result Output zval (will be array or original string)
 * @return true if parsed as JSON, false otherwise
 */
bool sf_try_parse_json(
    const char *value,
    size_t value_len,
    zval *result
);

/**
 * Check if a string looks like JSON (quick heuristic)
 *
 * @param value Value string
 * @param value_len Length of value
 * @return true if looks like JSON
 */
bool sf_looks_like_json(const char *value, size_t value_len);

#endif /* SF_DOTENV_PARSER_H */
