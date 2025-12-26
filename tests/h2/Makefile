CFLAGS  += -ggdb -Og -Wall -DDEBUG=1 -DUNUSEDRESULT_DEBUG=1 -I/opt/openssl-3.0.0/include -I/usr/local/include
LDFLAGS += -L/opt/openssl-3.0.0/lib64 -L/usr/local/lib
LDLIBS  += -lnghttp2 -lssl -lcrypto

C_FILES := $(wildcard *.c)
EXECUTABLES := $(C_FILES:.c=)

default: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
