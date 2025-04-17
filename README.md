
# ORRvsTNvsKR 🚀

## 🌟 Overview

This repository provides the code necessary to carry out performance tests between the key distribution models in Quantum Key Distribution Networks (QKDN):

- **Key-Relay (KR)** 🔑  
- **Trusted-Node (TN)** 🛡️  
- **Onion-Routing-Relay (ORR)** 🧅  
- **ORR-Extended (ORR-EXT)** 🧅🔒

The project implements cryptographic techniques, including **Post-Quantum Cryptography (PQC)** and **Quantum Key Distribution (QKD)**, to ensure secure communication.

---

## 📦 Dependencies

This project requires the following libraries:

- `libcurl` (HTTP client) 🌐  
- `jansson` (JSON parsing) 📄  
- `liboqs` (Post-quantum cryptography) 🔐  
- `OpenSSL` (Cryptographic functions) 🔒  
- `libb64` (Base64 encoding/decoding) 🧬  
- `pthreads` (Threading support) 🧵  

---

## 🛠️ Installation

On Debian/Ubuntu systems, install dependencies with:

```bash
sudo apt update
sudo apt install build-essential libcurl4-openssl-dev libjansson-dev libssl-dev libb64-dev
# Note: liboqs may need to be compiled from source
```

---

## ⚙️ Building the Project

### 🔧 Compilation with Makefile

```bash
# Build all components
make

# Clean build artifacts
make clean
```

### 🛠️ Manual Compilation

```bash
gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o key_relay key_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o trusted_node trusted_node.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o or_relay or_relay.c kms/kms.c onion/onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
gcc -DNUM_WORKERS=5 -DNUM_EXEC=2 -o or_relay or_relay.c kms/kms.c onion/onion.c new_onion/new_onion.c -lcurl -ljansson -loqs -lpthread -lssl -lcrypto -lb64
```

> ℹ️ Parameter `NUM_WORKERS` indicate the number of routers in the onion circuit and `NUM_EXEC` indicate the number of simulations to be done (specially useful for testing).
---

## 🚀 Usage

- **Key Relay** 🔑  
  ```bash
  ./key_relay.o
  ```

- **Trusted Node** 🛡️  
  ```bash
  ./trusted_node.o
  ```

- **Onion Routing Relay** 🧅  
  ```bash
  ./or_relay.o
  ```

- **Onion Routing Relay Extended** 🧅🔒  
  ```bash
  ./or_relay_ext.o
  ```

For testing is more useful use the script `test.sh`, where different parameter for testing can be customized.

---

## 📂 Project Structure

```
├── key_relay.c                 # Key management relay implementation
├── kms/
│   ├── certs/                  # Certificates folder
│   │   ├── alice/
│   │   │   ├── private-key.pem 
│   │   │   └── public.pem
│   │   ├── bob/
│   │   │   ├── private-key.pem
│   │   │   └── public.pem
│   │   └── ca/
│   │       └── rootCA.pem
│   ├── kms.c                   # KMS implementation
│   └── kms.h                   # KMS header
├── onion/
│   ├── onion.c                 # Onion protocol implementation
│   └── onion.h                 # Onion protocol headers
├── or_relay.c                  # Onion routing relay implementation
├── trusted_node.c              # Trusted node implementation
├── Makefile                    # Build automation
└── README.md                   # Project documentation
```

---

## 🔑 Certificates

The `certs/` folder must contain the necessary certificates to communicate with the QKD nodes:

```
certs/
├── alice/
│   ├── private-key.pem
│   └── public.pem
├── bob/
│   ├── private-key.pem
│   └── public.pem
└── ca/
    └── rootCA.pem
```

> ⚠️ The route to each certificate and the addresses for the HTTPs request to both QKD nodes must be defined in `kms/kms.c`.

> ℹ️ In the absence of real QKD nodes, online simulators like [QuKayDee](https://qukaydee.com/pages/getting_started) can be used.

---

## 📊 Results and Analysis

### 🧪 Simulation Script

```bash
./test.sh
```

### 📈 Data Processing

```bash
python3 process.py
```

### 🖼️ Graph Generation

```bash
python3 graphs.py
```

### 📁 Output Files

- **Raw Data:**
  - `key_distribution.out`
  - `encryption_time.out`

- **Processed Data:**
  - `results/key_distribution_avs.csv`
  - `results/encryption_time_avs.csv`

- **Graphs:**
  - `results/key_distribution_comparison.png`
  - `results/encryption_time_comparison.png`

---

## 📜 License

This project is licensed under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC-BY-NC-SA 4.0)**.

For more information, see the full license text: [CC-BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)

---

## 🙌 Acknowledgments

- **Open Quantum Safe (OQS)** for post-quantum cryptographic libraries.  
- **OpenSSL** for cryptographic primitives.  

---