#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include "httplib.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

using namespace std;

// Structure to store scan results
struct PortResult {
    int port;
    string service;
    string banner;
    string riskLevel;
    string description;
};

// Flag common vulnerable ports and identify services
void analyzePort(int port, string& service, string& riskLevel, string& description) {
    switch (port) {
        case 21:
            service = "FTP";
            riskLevel = "High";
            description = "Unencrypted file transfer. Banners may expose software version.";
            break;
        case 22:
            service = "SSH";
            riskLevel = "Low";
            description = "Encrypted remote access protocol.";
            break;
        case 23:
            service = "Telnet";
            riskLevel = "Critical";
            description = "FLAGGED: Unencrypted clear-text protocol! Highly vulnerable to interception.";
            break;
        case 25:
            service = "SMTP";
            riskLevel = "Medium";
            description = "Mail delivery protocol. Verify open-relay configurations.";
            break;
        case 80:
            service = "HTTP";
            riskLevel = "Info";
            description = "Standard web server port.";
            break;
        case 110:
            service = "POP3";
            riskLevel = "Medium";
            description = "Unencrypted mail retrieval protocol.";
            break;
        case 139:
        case 445:
            service = "SMB / NetBIOS";
            riskLevel = "High";
            description = "FLAGGED: File sharing protocol. Common target for network exploits.";
            break;
        case 3306:
            service = "MySQL";
            riskLevel = "Medium";
            description = "Database port exposed to network.";
            break;
        case 3389:
            service = "RDP";
            riskLevel = "High";
            description = "FLAGGED: Remote Desktop Protocol exposed to network attacks.";
            break;
        case 8080:
            service = "HTTP-Proxy";
            riskLevel = "Info";
            description = "Alternative web server or proxy port.";
            break;
        default:
            service = "Unknown Service";
            riskLevel = "Info";
            description = "Custom or unrecognized service detected.";
            break;
    }
}

// Perform TCP connect scan and banner grab on a port
bool tryConnectAndGrabBanner(const string& ip, int port, string& bannerOut) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    // Set connection timeout to 800 milliseconds
#ifdef _WIN32
    DWORD timeout = 800;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 800000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    // Attempt TCP socket connection
    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    // Attempt banner grab (read initial response)
    char buffer[256] = {0};
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);

    // If no initial banner sent, send a basic probe request
    if (bytesReceived <= 0) {
        string probe = "HEAD / HTTP/1.0\r\n\r\n";
        send(sock, probe.c_str(), (int)probe.length(), 0);
        bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    }

    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        string rawBanner(buffer);
        
        // Clean banner text for JSON formatting
        string cleaned = "";
        for (char c : rawBanner) {
            if (c >= 32 && c <= 126) {
                if (c == '"' || c == '\\') cleaned += '\\';
                cleaned += c;
            } else if (c == '\n' || c == '\r') {
                cleaned += " ";
            }
        }
        bannerOut = cleaned.substr(0, 80);
    } else {
        bannerOut = "No banner returned";
    }

    closesocket(sock);
    return true;
}

// Thread worker function for port range scanning
void scanWorker(const string& ip, const vector<int>& portsToScan, atomic<size_t>& indexCounter, vector<PortResult>& results, mutex& resultsMutex) {
    while (true) {
        size_t idx = indexCounter.fetch_add(1);
        if (idx >= portsToScan.size()) break;

        int port = portsToScan[idx];
        string banner = "";

        if (tryConnectAndGrabBanner(ip, port, banner)) {
            PortResult res;
            res.port = port;
            res.banner = banner;
            analyzePort(port, res.service, res.riskLevel, res.description);

            lock_guard<mutex> lock(resultsMutex);
            results.push_back(res);
        }
    }
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    httplib::Server svr;

    cout << "=================================================" << endl;
    cout << " Multithreaded TCP Socket Server listening on 8080 " << endl;
    cout << "=================================================" << endl;

    svr.Get("/scan", [](const httplib::Request& req, httplib::Response& res) {
        string ip = req.get_param_value("ip");
        string startStr = req.get_param_value("startPort");
        string endStr = req.get_param_value("endPort");
        string threadsStr = req.get_param_value("threads");

        if (ip.empty()) ip = "127.0.0.1";
        int startPort = startStr.empty() ? 1 : stoi(startStr);
        int endPort = endStr.empty() ? 1024 : stoi(endStr);
        int numThreads = threadsStr.empty() ? 10 : stoi(threadsStr);

        // Sanitize bounds
        if (startPort < 1) startPort = 1;
        if (endPort > 65535) endPort = 65535;
        if (startPort > endPort) swap(startPort, endPort);
        if (numThreads < 1) numThreads = 1;
        if (numThreads > 50) numThreads = 50;

        vector<int> portsToScan;
        for (int p = startPort; p <= endPort; p++) {
            portsToScan.push_back(p);
        }

        vector<PortResult> results;
        mutex resultsMutex;
        atomic<size_t> indexCounter(0);
        vector<thread> workerThreads;

        for (int i = 0; i < numThreads; i++) {
            workerThreads.emplace_back(scanWorker, ip, ref(portsToScan), ref(indexCounter), ref(results), ref(resultsMutex));
        }

        for (auto& t : workerThreads) {
            if (t.joinable()) t.join();
        }

        // Sort results by port number
        sort(results.begin(), results.end(), [](const PortResult& a, const PortResult& b) {
            return a.port < b.port;
        });

        // Generate JSON response
        string json = "[";
        for (size_t i = 0; i < results.size(); i++) {
            if (i > 0) json += ",";
            json += "{";
            json += "\"port\":" + to_string(results[i].port) + ",";
            json += "\"service\":\"" + results[i].service + "\",";
            json += "\"banner\":\"" + results[i].banner + "\",";
            json += "\"risk\":\"" + results[i].riskLevel + "\",";
            json += "\"description\":\"" + results[i].description + "\"";
            json += "}";
        }
        json += "]";

        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_content(json, "application/json");
    });

    svr.listen("localhost", 8080);
    return 0;
}