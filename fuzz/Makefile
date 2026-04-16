# Signalforge dotenv fuzzer
#
# Builds a libFuzzer binary against the parser sources. A minimal Zend
# API shim (../../fuzz-support) replaces libphp so ASan has byte-level
# precision on every allocation without needing php-embed.
#
# Usage:
#   make                # build harness
#   make run            # 5-minute run against the seed corpus
#   make run-long       # 1-hour run
#   make clean

CC       := clang
SHIM     := ../../fuzz-support
SRCS     := harness.c \
            $(SHIM)/php_stubs.c \
            ../src/parser.c
CFLAGS   := -fsanitize=fuzzer,address,undefined \
            -fno-sanitize-recover=all \
            -fno-omit-frame-pointer \
            -g -O1 -Wall \
            -I$(SHIM) -I../src
LDFLAGS  := -L/usr/lib/gcc/x86_64-linux-gnu/13

# libFuzzer's flag vocabulary:
#   -max_total_time: stop after N seconds
#   -print_final_stats=1: emit coverage counters at exit
#   -artifact_prefix: where to save crashing inputs
RUN_ARGS := corpus/ -print_final_stats=1 -artifact_prefix=artifacts/

harness: $(SRCS) $(SHIM)/php_stubs.h
	@mkdir -p artifacts
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

run: harness
	SF_FUZZ_QUIET=1 ./harness $(RUN_ARGS) -max_total_time=300

run-long: harness
	SF_FUZZ_QUIET=1 ./harness $(RUN_ARGS) -max_total_time=3600

clean:
	rm -f harness
	rm -rf artifacts

.PHONY: run run-long clean
