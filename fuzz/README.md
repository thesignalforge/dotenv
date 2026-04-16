# Signalforge dotenv parser fuzzer

libFuzzer + ASan + UBSan harness for `sf_parser_parse()` in
`../src/parser.c`, plus the `${VAR}` expansion pass via
`sf_expand_variables()`.

## Running locally

```bash
make           # build harness (requires clang with libfuzzer)
make run       # 5-minute run, stats printed at exit
make run-long  # 1-hour run
make clean
```

Artefacts (crashes, leaks, timeouts) are written to `artifacts/`.
Silence parser warnings with `SF_FUZZ_QUIET=1` (the Makefile sets it
automatically for `make run`).

## Requirements

- clang 14+ with `-fsanitize=fuzzer,address,undefined`
- The shim in `../../fuzz-support/` replaces libphp so no PHP install
  is needed to build.

## What is fuzzed

The harness feeds raw bytes to `sf_parser_parse()`, then:

1. For every successfully parsed key/value, runs `sf_expand_variables()`
   against the partial HashTable. This exercises the `${VAR}`,
   `${VAR:-default}`, `${VAR:+alt}`, and `$VAR` scanners plus cycle
   detection.
2. Destroys both the result hashtable and the parser context, so leaks
   on either path are flagged by ASan at process exit.

## Seed corpus

`corpus/` contains 15 hand-picked seeds:

- `seed_001_minimal`: single `FOO=bar`
- `seed_002_typical`: realistic 9-key `.env`
- `seed_003_expansion`: `export`, `${A}@${B}:${C}`, `${X:-default}`, `${Y:+alt}`
- `seed_004_quotes`: single/double/backtick, empty value, key-only, whitespace
- `seed_005_json`: `KEY={"a":1}` and array-valued entries
- `seed_006_escapes`: `\n`, `\t`, `\"`, `\$`, `\\`
- `seed_007_empty`: 0 bytes
- `seed_008_single_equals`: just `=`
- `seed_009_newlines`: blank lines only
- `seed_010_comment_only`: `#`
- `seed_011_circular`: `A=${B}`, `B=${A}` — regression for the circular-expansion fix
- `seed_012_indirect_circular`: `A=${B}`, `B=${C}`, `C=${A}`
- `seed_013_unterminated`: open `"` never closed
- `seed_014_unclosed_expansion`: `"${X` with newline inside
- `seed_015_redefinition`: same key three times

## Known limitations

- The harness runs against a shim Zend API (see `../../fuzz-support/
  php_stubs.h`); bugs that depend on real Zend-arena behaviour - e.g.
  interned-string identity comparisons - won't be caught here.
- JSON parsing is a stub. `PHP_JSON_OBJECT_AS_ARRAY` parse errors
  reported by `sf_try_parse_json()` are not reachable; fuzz this path
  via the end-to-end phpt test suite.

## Current state (last run on this codebase)

- 4.8M executions in 5 minutes
- 868 edge-coverage points
- 0 crashes, 0 leaks, 0 UBSan violations
