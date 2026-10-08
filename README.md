
# Vulnerability Scanner (Basic Port Scanner)

**CyberScan** is a high-performance, multithreaded network security auditing application built with a native C++17 Winsock engine backend and a futuristic, neon-styled web frontend. It bridges low-level C++ network socket programming with modern web UI technologies to deliver fast, real-time port scanning, service banner detection, and security threat evaluation.

---

## 📋 Table of Contents

- [Features](#features)
- [How It Works (System Architecture)](#-how-it-works-system-architecture)
- [Project Directory Structure](#-project-directory-structure)
- [Prerequisites and System Requirements](#prerequisites-and-system-requirements)
- [How to Build and Run (Usage Guide)](#how-to-build-and-run-usage-guide)
  - [Option 1: Quick Modular Setup](#option-1-quick-modular-setup)
  - [Option 2: Ultimate Standalone All-In-One Executable (`.exe`)](#option-2-ultimate-standalone-all-in-one-executable-exe)
- [How to Use the Dashboard](#-how-to-use-the-dashboard)
- [Detailed Code Architecture](#-detailed-code-architecture)
- [REST API Reference](#-rest-api-reference)
- [Troubleshooting & FAQ](#-troubleshooting--faq)
- [Legal & Ethical Disclaimer](#legal--ethical-disclaimer)

---

##  Features

* ** Multithreaded C++ Engine**: Spawns non-blocking thread pools (`std::thread`) to scan hundreds of ports concurrently in seconds.
* ** Thread-Safe Execution**: Employs mutual exclusion primitives (`std::mutex` and `std::lock_guard`) to prevent race conditions during result aggregation.
* ** Low-Level Socket Operations**: Utilizes native Windows Sockets (`Winsock2`) with configurable connection timeouts (1000ms) to bypass non-responsive or dropped packets.
* **Automatic Service Detection**: Maps discovered open ports to standard protocols (HTTP, HTTPS, FTP, SSH, MySQL, etc.) and analyzes banner output.
* ** Threat & Risk Classification**: Automatically evaluates open ports and assigns threat ratings (`Low`, `Medium`, `High`, `Critical`).
* **Embedded HTTP REST API**: Built on `httplib.h` serving a JSON API on port `8080`.
* ** Modern Cyberpunk Interface**: Dark-mode glassmorphic dashboard featuring live terminal streaming, interactive search/filter, progress feedback, and data export options.
* ** Single-File Executable Distribution**: Embeds the full frontend (HTML, CSS, JS) into C++ memory, creating a single `.exe` file that boots the server and automatically pops open your default web browser on launch.

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

```

1. **API Handler**: The user sends scan parameters (`ip`, `startPort`, `endPort`, `threads`) via HTTP GET to `/scan`.
2. **Batch Dispatcher**: The C++ engine splits the port range into chunks defined by the `threads` parameter.
3. **Socket Probe**: Each thread opens a TCP socket using `socket()` and `connect()` with a 1-second timeout.
4. **Data Synchronization**: If `connect()` succeeds, thread-safe memory locking (`std::lock_guard`) captures port details into the results array.
5. **JSON Delivery**: Results are serialized into JSON format and returned to the web interface.

---

## 📁 Project Directory Structure

### Standard Layout

```text
cyber-scan/
├── index.html        # Web UI markup and layout
├── style.css         # Visual styling, glassmorphism, and neon theme
├── script.js         # Event listeners, API handlers, DOM manipulation
├── httplib.h         # Header-only C++ HTTP server library
├── main.cpp          # C++ backend engine, socket logic, and API router
└── README.md         # Documentation

```

---

## Prerequisites and System Requirements

* **Operating System**: Windows 10 or Windows 11 (64-bit).
* **Compiler**: GCC / MinGW-w64 with support for **C++17** or higher (`g++`).
* **Required System Libraries**:
  * `Winsock2` (`ws2tcpip.h` / `-lws2_32` linker flag)
  * C++ Threading Library (`<thread>`, `<mutex>`)
---

##  How to Build and Run (Usage Guide)

### Option 1: Quick Modular Setup

This setup uses separate frontend (`index.html`) and backend C++ files.

1. Open your terminal in VS Code or Command Prompt inside the project folder.
2. Compile the backend executable:
```powershell
g++ main.cpp -o CyberScan.exe -std=c++17 -D_WIN32_WINNT=0x0A00 -lws2_32

```


3. Launch the compiled engine:
```powershell
.\CyberScan.exe

```


4. Double-click `index.html` or open it in your web browser.

---

### Option 2: Ultimate Standalone All-In-One Executable (`.exe`)

This setup embeds the entire UI (HTML, CSS, JS) directly inside `main.cpp` using raw string literals (`R"rawhtml(...)")`), creating a single executable file that automatically launches your browser.

1. Paste the complete single-file `main.cpp` code into your project.
2. Compile the standalone binary:
```powershell
g++ main.cpp -o CyberScanApp.exe -std=c++17 -D_WIN32_WINNT=0x0A00 -lws2_32

```


3. Run the application:
```powershell
.\CyberScanApp.exe

```


*(Or double-click `CyberScanApp.exe` directly in Windows File Explorer)*

---

## 💻 How to Use the Dashboard

Once `CyberScan.exe` or `CyberScanApp.exe` is running, your web browser will open to `http://localhost:8080`.

1. **Set Target IP**:
* Enter `127.0.0.1` to scan your local system safely.
* Or enter a remote IPv4 address on your authorized network.


2. **Define Port Range**:
* **Start Port**: Set to `1`
* **End Port**: Set to `1024` (or `8080` for common web services).


3. **Set Concurrency**:
* Select `10`, `25`, or `50` threads depending on your desired execution speed.


4. **Run the Scan**:
* Click **"Launch Scan Engine"**.
* Watch live status updates appear in the **Live Telemetry Stream**.
* Discovered open ports will appear in the **Discovered Services Table** with protocol and risk-level metrics.



---

## 🔍 Detailed Code Architecture

### Key Components in `main.cpp`

* **Target Operating System Macros**:
```cpp
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00

```


Informs MinGW to compile for modern Windows 10/11 API structures.
* **Result Structure**:
```cpp
struct ScanResult {
    int port;
    string service;
    string banner;
    string risk;
    string description;
};

```


* **Thread-Safe Memory Management**:
```cpp
mutex resultMutex;
vector<ScanResult> results;

```


`resultMutex` ensures that multiple worker threads do not write to the shared `results` vector simultaneously.
* **Socket Probing & Connection Timeouts**:
```cpp
SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
DWORD timeout = 1000;
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

```


Applies a hard 1-second connection timeout on socket operations to prevent worker threads from hanging on closed/unresponsive ports.
* **Automatic Browser Trigger**:
```cpp
thread([]() {
    this_thread::sleep_for(chrono::milliseconds(500));
    ShellExecute(NULL, "open", "http://localhost:8080", NULL, NULL, SW_SHOWNORMAL);
}).detach();

```


Spawns a background thread that invokes the Windows system API `ShellExecute` to open `http://localhost:8080` in your primary web browser automatically upon server startup.

---

## 📡 REST API Reference

### **Endpoint**: `GET /scan`

Executes a multithreaded TCP port scan against specified target parameters.

#### **Query Parameters**

| Parameter | Type | Required | Description | Example |
| --- | --- | --- | --- | --- |
| `ip` | `string` | Yes | Target host IP address | `127.0.0.1` |
| `startPort` | `integer` | Yes | Beginning port number (1-65535) | `1` |
| `endPort` | `integer` | Yes | Ending port number (1-65535) | `1024` |
| `threads` | `integer` | Yes | Concurrent worker threads | `25` |

#### **Sample JSON Response**

```json
[
  {
    "port": 21,
    "service": "FTP",
    "risk": "High"
  },
  {
    "port": 80,
    "service": "HTTP",
    "risk": "Low"
  }
]

```

---

## ❓ Troubleshooting & FAQ

### 1. Linker Error: `undefined reference to WSAStartup` or `closesocket`

* **Cause**: The Windows Socket library (`ws2_32`) was not linked during compilation.
* **Solution**: Ensure `-lws2_32` is included at the end of your GCC command:
`g++ main.cpp -o CyberScan.exe -std=c++17 -D_WIN32_WINNT=0x0A00 -lws2_32`

### 2. Browser displays "Connection Refused"

* **Cause**: Port `8080` is in use by another application or the C++ process was closed.
* **Solution**: Ensure `CyberScan.exe` remains active in your terminal window. Check Task Manager to close conflicting background processes using port `8080`.

---

## Legal & Ethical Disclaimer
---

CyberScan is created strictly for **educational purposes, defensive security auditing, and local network administrative testing**.

* **Authorized Use Only**: Scanning networks or systems without express written consent from the owner is illegal under cybercrime legislation.
* **No Liability**: The developers assume no responsibility or liability for any misuse or unauthorized network disruptions caused by this software.

---

```
