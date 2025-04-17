# Compiler and flags
CC = gcc
# CFLAGS = -DNUM_WORKERS=5 \
# 	-DNUM_EXEC=2 \
# 	-DWAIT_TIME=5 \
# 	-DDB_KEY_DIST=\"results/key_distribution.out\" \
# 	-DDB_ENC_TIME=\"results/encryption_time.out\"
CFLAGS =
LIBS = -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
SRC_COMMON = kms/kms.c onion/onion.c

# Targets
all: or_relay_ext.o key_relay.o trusted_node.o or_relay.o

or_relay_ext.o: or_relay_ext.c
	$(CC) $(CFLAGS) -o $@ $< $(SRC_COMMON) onion/new_onion.c $(LIBS)

key_relay.o: key_relay.c
	$(CC) $(CFLAGS) -o $@ $< $(SRC_COMMON) $(LIBS)

trusted_node.o: trusted_node.c
	$(CC) $(CFLAGS) -o $@ $< $(SRC_COMMON) $(LIBS)

or_relay.o: or_relay.c
	$(CC) $(CFLAGS) -o $@ $< $(SRC_COMMON) $(LIBS)

clean:
	rm -f or_relay_ext.o key_relay.o trusted_node.o or_relay.o