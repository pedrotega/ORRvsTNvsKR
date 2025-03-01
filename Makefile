CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64

SRC_DIR = .
KMS_DIR = kms
ONION_DIR = onion

COMMON_SRCS = $(KMS_DIR)/kms.c $(ONION_DIR)/onion.c
EXECUTABLES = key_relay or_relay trusted_node

all: $(EXECUTABLES)

key_relay: $(SRC_DIR)/key_relay.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

or_relay: $(SRC_DIR)/or_relay.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

trusted_node: $(SRC_DIR)/trusted_node.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLES) *.o

.PHONY: all clean