#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <windows.h>  // For CreateProcess

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9090
#define PACKET_BUFFER_SIZE 65536
#define MAX_BLOCK_COUNT 4  

volatile int running = 1;
pcap_t *handle = NULL;
SOCKET log_socket;
char blocked_ips[100][INET_ADDRSTRLEN];
int block_count[100] = {0};
int block_index = 0;

#pragma pack(push, 1)
struct iphdr {
    unsigned char ihl : 4, version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned char doff : 4, res1 : 4;
    unsigned char flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};
#pragma pack(pop)

void block_ip_and_port(const char *ip, int port) {
    char command[256];
    snprintf(command, sizeof(command),
             "netsh advfirewall firewall add rule name=\"Block %s:%d\" dir=in action=block remoteip=%s protocol=TCP remoteport=%d >nul 2>&1",
             ip, port, ip, port);
    system(command);
}

char *current_time() {
    static char buffer[30];
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

int should_block(const char *ip, int port) {
    for (int i = 0; i < block_index; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            block_count[i]++;
            if (block_count[i] > MAX_BLOCK_COUNT) {
                block_ip_and_port(ip, port);
                return 1;
            }
            return 0;
        }
    }

    if (block_index < 100) {
        strcpy(blocked_ips[block_index], ip);
        block_count[block_index] = 1;
        block_index++;
    }
    return 0;
}

void extract_packet_info(const u_char *packet, int len) {
    if (len < 34) return;

    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    if (!ip_header) return;

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ihl * 4));
    if (!tcp_header) return;

    struct sockaddr_in source, dest;
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char *src_ip = inet_ntoa(source.sin_addr);
    char *dst_ip = inet_ntoa(dest.sin_addr);
    int src_port = ntohs(tcp_header->source);
    int dst_port = ntohs(tcp_header->dest);

    if (should_block(src_ip, src_port)) return;

    char packet_info[256];
    snprintf(packet_info, sizeof(packet_info),
             "[%s] SRC: %s: %d -> DST: %s: %d | Size: %d bytes | TTL: %d | Protocol: %d\n",
             current_time(), src_ip, src_port, dst_ip, dst_port, len, ip_header->ttl, ip_header->protocol);

    int result = send(log_socket, packet_info, strlen(packet_info), 0);
    
    if (result == SOCKET_ERROR) {
        printf("\n[!] Connection lost. Stopping Firewall...\n");
        running = 0;
        if (handle) pcap_breakloop(handle);
        closesocket(log_socket);
        WSACleanup();
        exit(0);
    }
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
        const char *shutdown_msg = "FIREWALL_SHUTDOWN";
        send(log_socket, shutdown_msg, strlen(shutdown_msg), 0);
        printf("\n[!] Stopping Firewall... Cleaning up.\n");
        running = 0;
        if (handle) pcap_breakloop(handle);
        closesocket(log_socket);
        WSACleanup();
        exit(0);
    }
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *packet) {
    if (!running) return;
    extract_packet_info(packet, header->len);
}

void launch_python_logger() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    const char *cmd = "python firewall_manager.py";

    if (!CreateProcess(NULL, (LPSTR)cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("[ERROR] Failed to start Python logger. Error code: %lu\n", GetLastError());
        exit(1);
    } else {
        printf("[INFO] Python logger launched successfully (PID: %lu).\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void wait_for_logger_connection() {
    struct sockaddr_in server;
    log_socket = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);

    int retries = 5;
    while (connect(log_socket, (struct sockaddr*)&server, sizeof(server)) < 0 && retries--) {
        printf("[INFO] Waiting for logger to start... Retrying in 800ms...\n");
        Sleep(800);
    }

    if (retries <= 0) {
        printf("[ERROR] Unable to connect to logger at %s:%d. Exiting.\n", SERVER_IP, SERVER_PORT);
        exit(1);
    }

    printf("[INFO] Connected to Python logger.\n");
}

int main() {
    WSADATA wsa;
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int choice, i = 0;

    signal(SIGINT, handle_signal);
    WSAStartup(MAKEWORD(2, 2), &wsa);

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("[ERROR] Failed to find network interfaces: %s\n", errbuf);
        return 1;
    }

    printf("Available Network Interfaces:\n");
    for (device = alldevs; device; device = device->next) {
        printf("  [%d] %s\n", ++i, device->description ? device->description : "Unknown Adapter");
    }

    if (i == 0) {
        printf("[ERROR] No interfaces found. Exiting.\n");
        return 1;
    }

    printf("Enter the number of the interface to use: ");
    scanf("%d", &choice);

    device = alldevs;
    for (i = 1; i < choice; i++) device = device->next;

    if (!device) {
        printf("[ERROR] Invalid choice.\n");
        return 1;
    }

    handle = pcap_open_live(device->name, PACKET_BUFFER_SIZE, 1, 1000, errbuf);
    if (!handle) {
        printf("[ERROR] Failed to open device: %s\n", errbuf);
        return 1;
    }

    // 🚀 Launch and connect to logger
    launch_python_logger();
    wait_for_logger_connection();

    printf("[INFO] Starting packet capture...\n");
    pcap_loop(handle, 0, packet_handler, NULL);

    printf("[INFO] Firewall loop exited. Cleaning up...\n");
    pcap_close(handle);
    closesocket(log_socket);
    WSACleanup();
    return 0;
}
