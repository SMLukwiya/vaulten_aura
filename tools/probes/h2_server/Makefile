CC ?= gcc
EXTRA_CFLAGS ?=
EXTRA_TARGETS ?=
CFLAGS = -Wall -I/opt/openssl-3.0.0/include -Wextra $(EXTRA_CFLAGS) -Wno-unused-parameter -Wno-unused-variable
NG_CFLAGS = -Wall -I/usr/include/nghttp2 -I/opt/openssl-3.0.0/include -Wextra $(EXTRA_CFLAGS) -Wno-unused-parameter -Wno-unused-variable
LDFLAGS += -lssl -lcrypto -lpthread
NG_LDFLAGS += -lnghttp2 -lssl -lcrypto -lpthread
ENABLE_DEBUG ?= 0

ifeq ($(ENABLE_DEBUG), 1)
	CFLAGS += -g -DDEBUG
endif

all: run_probe ng_probe

SCENARIOS = scenarios/connection_preface.c scenarios/headers.c scenarios/continuation.c

run_probe: run_probe.c utils.c frame.c hpack.c probe.c $(SCENARIOS) $(EXTRA_TARGETS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ng_probe: nghttp_probe.c utils.c $(EXTRA_TARGETS)
	$(CC) $(NG_CFLAGS) -o $@ $^ $(NG_LDFLAGS)

clean:
	rm -rf run_probe ng_probe

.PHONY: all clean