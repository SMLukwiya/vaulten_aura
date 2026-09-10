CC ?= gcc
EXTRA_CFLAGS ?=
EXTRA_TARGETS ?=
CFLAGS = -Wall -I/usr/include/nghttp2 -I/opt/openssl-3.0.0/include -Wextra $(EXTRA_CFLAGS) -Wno-unused-parameter -Wno-unused-variable
LDFLAGS += -lnghttp2 -lssl -lcrypto -lpthread
ENABLE_DEBUG ?= 0

ifeq ($(ENABLE_DEBUG), 1)
	CFLAGS += -g -DDEBUG
endif

all: tls_probe h2_probe

tls_probe: tls_probe.c utils.c $(EXTRA_TARGETS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

h2_probe: h2_probe.c utils.c $(EXTRA_TARGETS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf tls_probe h2_probe

.PHONY: all clean