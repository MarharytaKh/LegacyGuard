ifeq ($(origin CC),default)
CC := gcc
endif
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
           -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=

BUILD   := build
SRC     := $(wildcard src/*.c)
LIB_SRC := $(filter-out src/main.c,$(SRC))
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/%.o)
TESTS   := $(patsubst tests/%.c,$(BUILD)/%,$(wildcard tests/test_*.c))
BIN     := legacyguard

.PHONY: all test asan valgrind demo clean

all: $(BIN)

$(BIN): $(BUILD)/main.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD)/%.o: src/%.c src/*.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/test_%: tests/test_%.c tests/minitest.h $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ $< $(LIB_OBJ) $(LDFLAGS)

$(BUILD):
	mkdir -p $@

test: $(TESTS)
	@set -e; for t in $(TESTS); do ./$$t; done

# Rebuild everything with AddressSanitizer + UBSan and run the tests.
asan:
	$(MAKE) clean
	$(MAKE) all test CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	             LDFLAGS="-fsanitize=address,undefined"

valgrind: $(BIN) $(TESTS)
	@set -e; for t in $(TESTS); do \
	    valgrind -q --leak-check=full --error-exitcode=1 ./$$t; done
	./scripts/demo.sh --valgrind

demo: $(BIN)
	./scripts/demo.sh

clean:
	rm -rf $(BUILD) $(BIN)
