# ⚡ CyberScan - C++ Multithreaded Port Scanner & Security Dashboard

**CyberScan** is a high-performance, multithreaded network security auditing application built with a native C++17 Winsock engine backend and a futuristic, neon-styled web frontend. It bridges low-level C++ network socket programming with modern web UI technologies to deliver fast, real-time port scanning, service banner detection, and security threat evaluation.

---

## 📋 Table of Contents

- [Features](#-features)
- [How It Works (System Architecture)](#-how-it-works-system-architecture)
- [Project Directory Structure](#-project-directory-structure)
- [Prerequisites & System Requirements](#-prerequisites--system-requirements)
- [How to Build and Run (Usage Guide)](#-how-to-build-and-run-usage-guide)
  - [Option 1: Quick Modular Setup](#option-1-quick-modular-setup)
  - [Option 2: Ultimate Standalone All-In-One Executable (`.exe`)](#option-2-ultimate-standalone-all-in-one-executable-exe)
- [How to Use the Dashboard](#-how-to-use-the-dashboard)
- [Detailed Code Architecture](#-detailed-code-architecture)
- [REST API Reference](#-rest-api-reference)
- [Troubleshooting & FAQ](#-troubleshooting--faq)
- [Legal & Ethical Disclaimer](#-legal--ethical-disclaimer)

---

## ✨ Features

* **⚡ Multithreaded C++ Engine**: Spawns non-blocking thread pools (`std::thread`) to scan hundreds of ports concurrently in seconds.
* **🔒 Thread-Safe Execution**: Employs mutual exclusion primitives (`std::mutex` and `std::lock_guard`) to prevent race conditions during result aggregation.
* **📡 Low-Level Socket Operations**: Utilizes native Windows Sockets (`Winsock2`) with configurable connection timeouts (1000ms) to bypass non-responsive or dropped packets.
* **🛠️ Automatic Service Detection**: Maps discovered open ports to standard protocols (HTTP, HTTPS, FTP, SSH, MySQL, etc.) and analyzes banner output.
* **🎯 Threat & Risk Classification**: Automatically evaluates open ports and assigns threat ratings (`Low`, `Medium`, `High`, `Critical`).
* **🌐 Embedded HTTP REST API**: Built on `httplib.h` serving a JSON API on port `8080`.
* **📊 Modern Cyberpunk Interface**: Dark-mode glassmorphic dashboard featuring live terminal streaming, interactive search/filter, progress feedback, and data export options.
* **📦 Single-File Executable Distribution**: Embeds the full frontend (HTML, CSS, JS) into C++ memory, creating a single `.exe` file that boots the server and automatically pops open your default web browser on launch.

---

## 🔬 How It Works (System Architecture)

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           BROWSER FRONTEND                              │
│   (index.html / embedded HTML + script.js + Neon CSS Glassmorphism UI)  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                        1. HTTP GET  │  5. JSON Response
                   /scan?ip=...      │  [ { "port": 80, ... } ]
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            C++ BACKEND ENGINE                           │
│                     (httplib.h Web Server on :8080)                     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
                        2. Dispatches Thread Pool
                                     │
           ┌─────────────────────────┼─────────────────────────┐
           ▼                         ▼                         ▼
   ┌───────────────┐         ┌───────────────┐         ┌───────────────┐
   │ Worker Thread │         │ Worker Thread │         │ Worker Thread │
   └───────┬───────┘         └───────┬───────┘         └───────┬───────┘
           │                         │                         │
           └─────────────────────────┼─────────────────────────┘
                                     │ 3. Non-blocking TCP Handshake
                                     ▼
                        ┌─────────────────────────┐
                        │     Target Network      │
                        │    (127.0.0.1 / Remote) │
                        └────────────┬────────────┘
                                     │
                                     │ 4. Result Lock Guard (std::mutex)
                                     ▼
                         ┌───────────────────────┐
                         │ vector<ScanResult>    │
                         └───────────────────────┘
