#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include <map>
#include <chrono>
#include <fstream>
#include <sstream>
#include <cstring>

using namespace std;

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>

#pragma comment(lib, "Ws2_32.lib")

// ঝুঁকিপূর্ণ পোর্টের তালিকা এবং সতর্কতা বার্তা
const map<int, string> VULNERABLE_PORTS = {
    {21, "FTP (Unencrypted credentials, vulnerable to brute force/anonymous login)"},
    {23, "Telnet (Completely unencrypted traffic, high risk of credential sniffing)"},
    {25, "SMTP (Relay exploitation, spam, enumeration)"},
    {53, "DNS (Zone transfers, amplification attacks)"},
    {69, "TFTP (No authentication, unencrypted file transfer)"},
    {80, "HTTP (Unencrypted web traffic, weak configuration)"},
    {110, "POP3 (Unencrypted email retrieval)"},
    {135, "RPC/RPCMAP (Information gathering, remote execution risks)"},
    {139, "NetBIOS (Information disclosure, SMB exploitation precursor)"},
    {445, "SMB (High risk: EternalBlue, ransomware propagation, credential dumping)"},
    {1433, "MSSQL (Brute force target, remote code execution bugs)"},
    {3306, "MySQL (Brute force target, privilege escalation risks)"},
    {3389, "RDP (BlueKeep vulnerability, brute force target, unauthorized access)"}
};

struct ScanResult {
    int port;
    string banner;
    string risk_flag;
};

// থ্রেড সিনক্রোনাইজেশনের জন্য ক্রিটিক্যাল সেকশন
CRITICAL_SECTION print_cs;
CRITICAL_SECTION queue_cs;
CRITICAL_SECTION results_cs;

queue<int> port_queue;
vector<ScanResult> open_ports;
string target_ip_global;

// হোস্টনেম বা ডোমেন থেকে আইপি অ্যাড্রেস বের করার ফাংশন
string resolve_target(const string& target) {
    struct hostent* he = gethostbyname(target.c_str());
    if (he == nullptr) return "";
    
    struct in_addr** addr_list = (struct in_addr**)he->h_addr_list;
    if (addr_list[0] != nullptr) {
        char* resolved_ip = inet_ntoa(*addr_list[0]);
        return resolved_ip ? string(resolved_ip) : "";
    }
    return "";
}

// সার্ভিস ব্যানার গ্র্যাব করার ফাংশন
string grab_banner(SOCKET sock) {
    // কিছু সার্ভিসকে ট্রিগার করার জন্য সাধারণ একটি রিকোয়েস্ট পাঠানো
    send(sock, "Hello\r\n", 7, 0);

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    // ব্যানার রিসিভ করার জন্য ২ সেকেন্ডের টাইমআউট
    DWORD tv = 2000; 
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    int bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received > 0) {
        string banner(buffer);
        for (char &c : banner) {
            if (c == '\n' || c == '\r') c = ' ';
        }
        if (banner.length() > 50) banner = banner.substr(0, 50) + "...";
        return banner;
    }
    return "No banner returned";
}

// একক পোর্ট স্ক্যান করার কোর ইঞ্জিন
void scan_port(const string& ip, int port) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

    // সকেটকে নন-ব্লকিং মোডে সেট করা (স্পিড অপ্টিমাইজেশন)
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    int conn_result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    bool is_open = false;

    if (conn_result == SOCKET_ERROR) {
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sock, &fdset);
            
            struct timeval tv;
            tv.tv_sec = 1; // ১.৫ সেকেন্ড কানেকশন টাইমআউট
            tv.tv_usec = 500000; 

            if (select(0, nullptr, &fdset, nullptr, &tv) > 0) {
                is_open = true; 
            }
        }
    } else {
        is_open = true;
    }

    // পোর্ট খোলা পাওয়া গেলে
    if (is_open) {
        // ব্যানার গ্র্যাব করার জন্য সকেটকে সাময়িক ব্লকিং মোডে ফেরত নেওয়া
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        
        string banner = grab_banner(sock);
        string risk_flag = "";
        
        // ঝুঁকির ডাটাবেজ চেক করা
        auto it = VULNERABLE_PORTS.find(port);
        if (it != VULNERABLE_PORTS.end()) {
            risk_flag = it->second;
        }

        // কনসোল আউটপুট প্রিন্ট লক (Thread safe)
        EnterCriticalSection(&print_cs);
        cout << "[+] Port " << port << " is OPEN | Banner: " << banner << "\n";
        if (!risk_flag.empty()) {
            cout << "    [!] ALERT: " << risk_flag << "\n";
        }
        LeaveCriticalSection(&print_cs);

        // রেজাল্ট ভেক্টরে ডেটা সেভ লক
        EnterCriticalSection(&results_cs);
        open_ports.push_back({port, banner, risk_flag});
        LeaveCriticalSection(&results_cs);
    }

    closesocket(sock);
}

// মাল্টিথ্রেডেড ওয়ার্কার ফাংশন
DWORD WINAPI worker_thread(LPVOID lpParam) {
    while (true) {
        int port = -1;
        
        // কিউ (Queue) থেকে পোর্ট তুলে নেওয়ার সময় লক
        EnterCriticalSection(&queue_cs);
        if (!port_queue.empty()) {
            port = port_queue.front();
            port_queue.pop();
        }
        LeaveCriticalSection(&queue_cs);

        if (port == -1) break; // কিউ খালি হলে থ্রেড বন্ধ হবে
        scan_port(target_ip_global, port);
    }
    return 0;
}

// মার্কডাউন ফরম্যাটে সিম্পল রিপোর্ট জেনারেশন
void generate_report(const string& target_ip, double duration) {
    string safe_ip = target_ip;
    for (char &c : safe_ip) if (c == '.') c = '_';
    string filename = "scan_report_" + safe_ip + ".md";

    ofstream file(filename);
    if (!file.is_open()) return;

    file << "# Security Scan Report for " << target_ip << "\n";
    file << "- **Duration:** " << duration << " seconds\n";
    file << "- **Total Open Ports Found:** " << open_ports.size() << "\n\n";
    
    file << "## Findings Summary\n";
    if (open_ports.empty()) {
        file << "No open ports were discovered during the scan execution scope.\n";
        file.close();
        return;
    }

    file << "| Port | Service Banner | Vulnerability / Risk Flag |\n";
    file << "| :--- | :--- | :--- |\n";

    for (const auto& item : open_ports) {
        string risk = item.risk_flag.empty() ? "Low Risk / Standard" : "⚠️ **" + item.risk_flag + "**";
        file << "| **" << item.port << "** | " << item.banner << " | " << risk << " |\n";
    }
    
    file.close();
    cout << "[-] Report successfully output to: " << filename << "\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <target_ip_or_domain> [start_port] [end_port] [threads]\n";
        return 1;
    }

    string target = argv[1];
    int start_port = (argc >= 3) ? stoi(argv[2]) : 1;
    int end_port = (argc >= 4) ? stoi(argv[3]) : 1024;
    int thread_count = (argc >= 5) ? stoi(argv[4]) : 50; // ৬০ এর নিচে রাখা নিরাপদ

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "[-] Error: Winsock initialization failed.\n";
        return 1;
    }

    target_ip_global = resolve_target(target);
    if (target_ip_global.empty()) {
        cerr << "[-] Error: Failed to resolve target host: " << target << "\n";
        WSACleanup();
        return 1;
    }

    InitializeCriticalSection(&print_cs);
    InitializeCriticalSection(&queue_cs);
    InitializeCriticalSection(&results_cs);

    cout << "============================================================\n";
    cout << "Scanning Target: " << target_ip_global << " (" << target << ")\n";
    cout << "Ports Vector   : " << start_port << " to " << end_port << "\n";
    cout << "Thread Ceiling : " << thread_count << "\n";
    cout << "============================================================\n";

    auto start_time = chrono::high_resolution_clock::now();

    // পোর্টের তালিকা কিউ-তে পুশ করা
    for (int p = start_port; p <= end_port; ++p) {
        port_queue.push(p);
    }

    vector<HANDLE> threads;
    for (int i = 0; i < thread_count; ++i) {
        HANDLE hThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);
        if (hThread != NULL) {
            threads.push_back(hThread);
        }
    }

    // একাধিক ব্লকে থ্রেড ম্যানেজমেন্ট (Windows MAX_WAIT_OBJECTS সীমাবদ্ধতা ফিক্স)
    for (size_t i = 0; i < threads.size(); i += 64) {
        size_t chunk = (threads.size() - i > 64) ? 64 : threads.size() - i;
        WaitForMultipleObjects(static_cast<DWORD>(chunk), &threads[i], TRUE, INFINITE);
    }

    for (HANDLE hThread : threads) {
        CloseHandle(hThread);
    }

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double> duration = end_time - start_time;

    cout << "============================================================\n";
    cout << "Scan finished cleanly inside " << duration.count() << " seconds.\n";
    
    generate_report(target_ip_global, duration.count());

    DeleteCriticalSection(&print_cs);
    DeleteCriticalSection(&queue_cs);
    DeleteCriticalSection(&results_cs);
    WSACleanup();
    return 0;
}