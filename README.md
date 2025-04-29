### Offloading TLS with Kernel TLS (kTLS) and OpenSSL

## 🌐 Introduction

In the era of high-speed networking and cloud infrastructure, **secure communication via TLS** is a must. But traditional TLS implementations burden the CPU with intensive encryption/decryption operations and frequent data copies between userspace and kernel space. This results in:

- High CPU usage  
- Redundant memory copies  
- Increased latency  
- Reduced throughput

To overcome these bottlenecks, **Kernel TLS (kTLS)** and **hardware offload using DPUs** offer a modern solution by pushing cryptographic workloads out of userspace.

This project demonstrates how to set up, test, and benchmark **TLS encryption offload** using **Linux kernel kTLS**, **OpenSSL**, and performance tools like `iperf3`.

---

## ⚡ TL;DR

This repo shows how to:

- Offload TLS encryption/decryption to the Linux kernel using **kTLS**
- Use **OpenSSL** for TLS handshakes and session key extraction
- Improve secure data transfer throughput with `sendfile()` and kTLS
- Benchmark performance vs traditional userspace TLS

---

## 🧠 Problem Statement

High-throughput environments like CDNs, financial networks, and cloud services demand **efficient secure communication**.

Traditional TLS stacks:
- Encrypt in userspace
- Incur high CPU overhead
- Perform redundant user-kernel transitions

We aim to optimize this by:
- Moving encryption into the **kernel**
- Reducing **CPU involvement**
- Using **zero-copy** data transfer

---

## 🏗️ Design & Architecture

### Goals
- Reduce CPU load
- Minimize memory copies
- Maximize encrypted throughput
- Maintain TLS-level security

### Modes Implemented

| Mode | Description |
|------|-------------|
| **Userspace TLS** | Standard OpenSSL over TCP |
| **kTLS with static keys** | Kernel encrypts, no real TLS handshake |
| **OpenSSL + kTLS** | Handshake via OpenSSL, encryption via kernel |

### Tools Used
- **OpenSSL**: TLS handshake, key negotiation
- **Linux Kernel kTLS**: TLS record encryption in kernel space
- **iperf3**, **htop**: Benchmarking tools

---

### 🔁 Data Flow Overview

- App → OpenSSL handshake → Extract keys
- Configure socket with `setsockopt()` → Kernel takes over encryption
- Use `sendfile()` to transfer data (zero-copy)
- NIC → Encrypted packet transmission

---

## 💻 Implementation Details

### 1. **Userspace TLS (OpenSSL + TCP)**

- TLS handshake via `SSL_connect()` / `SSL_accept()`
- Data exchange via `SSL_write()` / `SSL_read()`

### 2. **kTLS with Static Keys**

- Manually create dummy keys and IVs
- Set crypto info with `setsockopt()` and `TCP_ULP`
- Send plaintext → kernel performs framing (no real encryption)

### 3. **kTLS + OpenSSL**

- Perform handshake normally using OpenSSL
- Extract session keys and IVs from OpenSSL
- Pass crypto info to kernel via `setsockopt()`
- Use `sendfile()` or `send()` → kernel encrypts the data

---

## 🧪 Testing & Benchmarking

### Test Setup
- **Platform**: Intel x86_64 (Ubuntu 22.04, Linux 6.8.0)
- **TLS Library**: OpenSSL 3.0.2 with kTLS support
- **Cipher Suite**: AES-GCM (TLS 1.2+)

### Test Process
- Transfer files: 10MB, 100MB, 1GB, 1.5GB, 2GB
- Metrics: Latency (ms), Throughput (MB/s)
- Tests repeated 5 times for accuracy

---

## 📚 What We Learned

- Offloading to **kTLS** reduces CPU usage and improves performance
- **sendfile() + kernel crypto** = fast, zero-copy secure transfer
- **Manual key injection** is great for validation, but not secure for production
- **OpenSSL integration** with kTLS is effective, though debugging kernel paths is hard

---

## 🧩 Limitations

- Limited cipher support (TLS 1.2 + AES-GCM only)
- RX offload is hardware-dependent
- Debugging kernel crypto is challenging

---

## 📎 Resources & References

### Tools and Frameworks
- OpenSSL 3.0.2 – TLS handshake
- Linux Kernel 6.8 – kTLS
- iperf3, htop – Benchmarking tools

### Documentation
- [Linux Kernel TLS Offload Docs](https://docs.kernel.org/networking/tls-offload.html)
- [kTLS Implementation Guide](https://docs.kernel.org/networking/tls.html)
- [FreeBSD TLS Offload Paper (PDF)](https://freebsdfoundation.org/wp-content/uploads/2020/07/TLS-Offload-in-the-Kernel.pdf)
- [NVIDIA DOCA kTLS SDK](https://docs.nvidia.com/doca/sdk/ktls+offloads/index.html)
- [Oracle kTLS Utils GitHub](https://github.com/oracle/ktls-utils.git)
- [F5 Blog on kTLS](https://www.f5.com/company/blog/nginx/improving-nginx-performance-with-kernel-tls)
