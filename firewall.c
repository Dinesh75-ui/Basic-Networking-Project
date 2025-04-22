#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

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

char *current_time() {
    static char buffer[30];
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return buffer;
}

int should_block(const char *ip) {
    for (int i = 0; i < block_index; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            block_count[i]++;
            return block_count[i] > MAX_BLOCK_COUNT;
        }
    }

    strcpy(blocked_ips[block_index], ip);
    block_count[block_index] = 1;
    block_index++;
    return 0;
}

void extract_packet_info(const u_char *packet, int len) {
    if (len < 34) return;

    struct iphdr *ip_header = (struct iphdr *)(packet + 14);
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ihl * 4));

    struct sockaddr_in source, dest;
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    char *src_ip = inet_ntoa(source.sin_addr);
    char *dst_ip = inet_ntoa(dest.sin_addr);
    int src_port = ntohs(tcp_header->source);
    int dst_port = ntohs(tcp_header->dest);

    if (should_block(src_ip)) return;

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

    Sleep(800); // Add a delay of 0.8 seconds (800 milliseconds)
}

void handle_signal(int sig) {
    if (sig == SIGINT) {
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

int main() {
    WSADATA wsa;
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int choice, i = 0;
    char buffer[20];

    signal(SIGINT, handle_signal);
    WSAStartup(MAKEWORD(2, 2), &wsa);

    pcap_findalldevs(&alldevs, errbuf);
    printf("Available Network Interfaces:\n");

    for (device = alldevs; device; device = device->next) {
        printf("  [%d] %s\n", ++i, device->description ? device->description : "Unknown Adapter");
    }
    printf("Enter the number of the interface to use: ");
    scanf("%d", &choice);
    
    device = alldevs;
    for (i = 1; i < choice; i++) device = device->next;

    handle = pcap_open_live(device->name, PACKET_BUFFER_SIZE, 1, 1000, errbuf);

    struct sockaddr_in server;
    log_socket = socket(AF_INET, SOCK_STREAM, 0);
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);

    connect(log_socket, (struct sockaddr*)&server, sizeof(server));

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    closesocket(log_socket);
    WSACleanup();
    return 0;
}
