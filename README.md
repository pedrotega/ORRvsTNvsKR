# ORRvsTNvsKR
This repository provides the code necessary to carry out thae performance test between the key distribution models in QKDN: Key-Relay, Trusted-Node and Onion-Routing-Relay.

## Dependencies
This project requires the following libraries:
- libcurl (HTTP client)
- jansson (JSON parsing)
- liboqs (Post-quantum cryptography)
- OpenSSL (Cryptographic functions)
- libb64 (Base64 encoding/decoding)
- pthreads (Threading support)

## Building the Project

### Prerequisites
Ensure you have the following libraries installed on your system:
```
libcurl4-openssl-dev
libjansson-dev
liboqs-dev
libssl-dev
libb64-dev
```

On Debian/Ubuntu systems, install dependencies with:
```bash
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev libb64-dev
# Note: liboqs may need to be compiled from source
```

### Compilation
The project can be compiled using the provided Makefile:

```bash
# Build all components
make

# Build individual components
make key_relay
make or_relay
make trusted_node

# Clean build artifacts
make clean
```

Alternatively, compile manually with:
```bash
gcc -o key_relay key_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
gcc -o or_relay or_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
gcc -o trusted_node trusted_node.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
```

## Usage

### Key Relay
```bash
./key_relay [options]
```

### Onion Relay
```bash
./or_relay [options]
```

### Trusted Node
```bash
./trusted_node [options]
```

## Project Structure
```
├── key_relay.c                 # Key management relay implementation
├── kms/                        # Key Management Service
│   ├── certs                   # Foulder with ther necessary certificates
│   │   ├── alice
│   │   │   ├── private-key.pem 
│   │   │   └── public.pem
│   │   ├── bob
│   │   │   ├── private-key.pem
│   │   │   └── public.pem
│   │   └── ca
│   │       └── rootCA.pem
│   ├── kms.c                   # KMS implementation
│   └── kms.h                   # KMS header
├── onion/                      # Onion routing implementation
│   ├── onion.c                 # Onion protocol implementation
│   └── onion.h                 # Onion protocol headers
├── or_relay.c                  # Onion routing relay implementation
├── trusted_node.c              # Trusted node implementation
├── Makefile                    # Build automation
└── README.md                   
```

## Certificates

The foulder `certs` must be created with the necessary certificates to communicate with the QKD nodes with the structure showed in the last section. 

In the absence of QKD nodes, online simulators such as the one provided by [QuKayDee](https://qukaydee.com/pages/getting_started) can be used.

