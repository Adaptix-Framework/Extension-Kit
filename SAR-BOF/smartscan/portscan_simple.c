#include <winsock2.h>
#include <windows.h>

#include "beacon.h"
#include "bofdefs.h"

__declspec(dllimport) unsigned long __stdcall WS2_32$inet_addr(const char *cp);
__declspec(dllimport) unsigned short __stdcall WS2_32$htons(unsigned short hostshort);
__declspec(dllimport) unsigned long __stdcall WS2_32$ntohl(unsigned long netlong);
DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket(int af, int type, int protocol);
__declspec(dllimport) int __stdcall WS2_32$ioctlsocket(SOCKET, long, u_long*);
__declspec(dllimport) int __stdcall WS2_32$connect(SOCKET, const struct sockaddr*, int);
__declspec(dllimport) int __stdcall WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
__declspec(dllimport) int __stdcall WS2_32$closesocket(SOCKET);
__declspec(dllimport) int __stdcall WS2_32$inet_pton(int, const char*, void*);
__declspec(dllimport) char* __stdcall WS2_32$inet_ntoa(struct in_addr);
__declspec(dllimport) int __stdcall WS2_32$WSAStartup(WORD, LPWSADATA);
__declspec(dllimport) int __stdcall WS2_32$WSACleanup(void);
__declspec(dllimport) int __stdcall WS2_32$getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen);
__declspec(dllimport) unsigned long __stdcall WS2_32$htonl(unsigned long hostlong);

#define DEFAULT_TIMEOUT    2000
#define MAX_PORTS          200
#define MAX_CONCURRENT     10
#define SCAN_BATCH_SIZE    8
#define BATCH_DELAY_MS     30

int g_level1_ports[] = {
    80, 443, 8080, 8443,
    1433, 1521, 3306, 5432, 6379, 27017,
    0
};

int g_level2_ports[] = {
    80, 443, 8080, 8443,
    1433, 1521, 3306, 5432, 6379, 27017,
    135, 139, 445, 3389, 5985, 5986,
    22,
    21, 25, 53, 110, 143, 993, 995,
    0
};

int g_level3_ports[] = {
    80, 443, 8080, 8443, 8000, 8888,
    1433, 1521, 3306, 5432, 6379, 27017, 9200, 9300,
    135, 139, 445, 3389, 5985, 5986, 88, 389, 636, 3268, 3269,
    22, 23,
    21, 25, 53, 69, 110, 111, 143, 993, 995,
    7, 9, 13, 19, 37, 79, 113, 119, 1025, 1434, 1604, 1723, 2000, 2001, 2048, 2049, 2100, 3128, 5000, 5060, 5061, 5900, 6000, 6667, 8081, 9000, 10000, 11211,
    0
};

void bofstart() {}
void bofstop() {}

int tcp_port_scan(const char* ip, int port, int timeout)
{
    SOCKET sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return 0;
    }

    u_long mode = 1;
    WS2_32$ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr;
    MSVCRT$memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = WS2_32$htons((unsigned short)port);

    unsigned long a = WS2_32$inet_addr(ip);
    if (a == INADDR_NONE) {
        WS2_32$closesocket(sock);
        return 0;
    }
    addr.sin_addr.s_addr = a;

    WS2_32$connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int result = WS2_32$select((int)(sock + 1), NULL, &write_set, NULL, &tv);

    if (result > 0) {
        int err = 0;
        int len = sizeof(err);
        if (WS2_32$getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len) == 0) {
            WS2_32$closesocket(sock);
            if (err == 0) {
                return 1;
            } else {
                return 0;
            }
        } else {
            WS2_32$closesocket(sock);
            return 0;
        }
    }

    WS2_32$closesocket(sock);
    return 0;
}


const char* get_service_name(int port)
{
    switch (port) {
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 69: return "tftp";
        case 70: return "gopher";
        case 79: return "finger";
        case 80: return "http";
        case 88: return "kerberos";
        case 110: return "pop3";
        case 135: return "rpc";
        case 139: return "netbios";
        case 143: return "imap";
        case 443: return "https";
        case 445: return "smb";
        case 993: return "imaps";
        case 995: return "pop3s";
        case 1433: return "mssql";
        case 1521: return "oracle";
        case 3306: return "mysql";
        case 3389: return "rdp";
        case 5432: return "postgres";
        case 5985: return "winrm";
        case 5986: return "winrm-ssl";
        case 6379: return "redis";
        case 8080: return "http-alt";
        case 8443: return "https-alt";
        case 27017: return "mongodb";
        default:
            if (port >= 70 && port <= 90) {
                return "custom";
            }
            return "unknown";
    }
}

int parse_single_ip(const char* target, char* ip_str)
{
    MSVCRT$strcpy(ip_str, target);
    return 1;
}

int parse_cidr_simple(const char* cidr, char*** ip_list, int* count)
{
    char base_ip[16];
    char* slash = MSVCRT$strchr(cidr, '/');

    if (!slash) {
        return 0;
    }

    int ip_len = slash - cidr;
    if (ip_len >= 16) {
        return 0;
    }

    MSVCRT$memcpy(base_ip, cidr, ip_len);
    base_ip[ip_len] = '\0';

    int mask = 0;
    const char* mask_ptr = slash + 1;
    while (*mask_ptr >= '0' && *mask_ptr <= '9') {
        mask = mask * 10 + (*mask_ptr - '0');
        mask_ptr++;
    }

    if (mask != 24) {
        BeaconPrintf(CALLBACK_ERROR, "Only /24 CIDR notation supported in this version\n");
        return 0;
    }

    char* last_dot = NULL;
    for (int i = 0; base_ip[i]; i++) {
        if (base_ip[i] == '.') {
            last_dot = &base_ip[i];
        }
    }
    if (!last_dot) {
        return 0;
    }

    int network_len = last_dot - base_ip + 1;

    *count = 254;
    *ip_list = (char**)intAlloc(*count * sizeof(char*));
    if (!*ip_list) {
        return 0;
    }

    for (int i = 0; i < *count; i++) {
        (*ip_list)[i] = (char*)intAlloc(16 * sizeof(char));
        if (!(*ip_list)[i]) {
            break;
        }

        MSVCRT$memcpy((*ip_list)[i], base_ip, network_len);
        MSVCRT$sprintf((*ip_list)[i] + network_len, "%d", i + 1);
    }

    return 1;
}

int parse_target_list_extended(const char* targets, char*** ip_list, int* count)
{
    if (!targets || !targets[0]) return 0;

    char* copy = (char*)intAlloc(MSVCRT$strlen(targets) + 1);
    if (!copy) return 0;
    MSVCRT$strcpy(copy, targets);

    char* token = MSVCRT$strtok(copy, ",");
    char** result = NULL;
    int total = 0;

    while (token)
    {
        while (*token == ' ') token++;

        char* end = token + MSVCRT$strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\r' || *end == '\n')) *end-- = '\0';

        char** tmp_list = NULL;
        int tmp_count = 0;

        if (MSVCRT$strchr(token, '/')) {
            if (!parse_cidr_simple(token, &tmp_list, &tmp_count)) {
                BeaconPrintf(CALLBACK_ERROR, "Invalid CIDR: %s\n", token);
                token = MSVCRT$strtok(NULL, ",");
                continue;
            }
        }
        else if (MSVCRT$strchr(token, '-')) {
            char start_ip[32] = {0}, end_ip[32] = {0};
            char* dash = MSVCRT$strchr(token, '-');
            if (!dash) { token = MSVCRT$strtok(NULL, ","); continue; }

            *dash = '\0';
            MSVCRT$strcpy(start_ip, token);
            MSVCRT$strcpy(end_ip, dash + 1);

            unsigned long start_a = WS2_32$inet_addr(start_ip);
            unsigned long end_a   = WS2_32$inet_addr(end_ip);

            if (start_a == INADDR_NONE || end_a == INADDR_NONE) {
                BeaconPrintf(CALLBACK_ERROR, "Invalid IP range: %s-%s\n", start_ip, end_ip);
                token = MSVCRT$strtok(NULL, ",");
                continue;
            }

            DWORD start = WS2_32$ntohl(start_a);
            DWORD end   = WS2_32$ntohl(end_a);
            if (end < start) {
                DWORD tmp = start; start = end; end = tmp;
            }

            DWORD range_size = end - start + 1;
            if (range_size > 1024) range_size = 1024;

            tmp_list = (char**)intAlloc(range_size * sizeof(char*));
            if (!tmp_list) break;

            for (DWORD i = 0; i < range_size; i++) {
                struct in_addr addr;
                addr.s_addr = WS2_32$htonl(start + i);
                tmp_list[i] = (char*)intAlloc(16);
                char *s = WS2_32$inet_ntoa(addr);
                if (s) {
                    MSVCRT$strcpy(tmp_list[i], s);
                } else {
                    MSVCRT$strcpy(tmp_list[i], "0.0.0.0");
                }
            }
            tmp_count = (int)range_size;
        }
        else {
            tmp_list = (char**)intAlloc(sizeof(char*));
            tmp_list[0] = (char*)intAlloc(16);
            MSVCRT$strcpy(tmp_list[0], token);
            tmp_count = 1;
        }

        char** new_result = (char**)intAlloc((total + tmp_count) * sizeof(char*));
        if (result) {
            for (int i = 0; i < total; i++) new_result[i] = result[i];
            intFree(result);
        }
        for (int j = 0; j < tmp_count; j++) new_result[total + j] = tmp_list[j];
        intFree(tmp_list);

        total += tmp_count;
        result = new_result;

        token = MSVCRT$strtok(NULL, ",");
    }

    intFree(copy);
    *ip_list = result;
    *count = total;

    return (total > 0);
}


int* parse_custom_ports(const char* port_spec, int* count)
{
    if (!port_spec || !port_spec[0]) {
        return NULL;
    }

    char* spec_copy = (char*)intAlloc(MSVCRT$strlen(port_spec) + 1);
    if (!spec_copy) {
        return NULL;
    }
    MSVCRT$strcpy(spec_copy, port_spec);

    *count = 0;
    char* token = MSVCRT$strtok(spec_copy, ",");
    while (token) {
        while (*token == ' ') token++;

        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            int start_port = 0, end_port = 0;

            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                start_port = start_port * 10 + (*ptr - '0');
                ptr++;
            }

            ptr = dash + 1;

            while (*ptr >= '0' && *ptr <= '9') {
                end_port = end_port * 10 + (*ptr - '0');
                ptr++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                int range_count = end_port - start_port + 1;
                if (range_count > 1000) {
                    range_count = 1000;
                }
                *count += range_count;
            }
        } else {
            int port = 0;
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                port = port * 10 + (*ptr - '0');
                ptr++;
            }

            if (port > 0 && port <= 65535) {
                (*count)++;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    if (*count == 0) {
        intFree(spec_copy);
        return NULL;
    }

    int* ports = (int*)intAlloc(*count * sizeof(int));
    if (!ports) {
        intFree(spec_copy);
        return NULL;
    }

    MSVCRT$strcpy(spec_copy, port_spec);
    int port_index = 0;

    token = MSVCRT$strtok(spec_copy, ",");
    while (token && port_index < *count) {
        while (*token == ' ') token++;

        char* dash = MSVCRT$strchr(token, '-');
        if (dash) {
            int start_port = 0, end_port = 0;

            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                start_port = start_port * 10 + (*ptr - '0');
                ptr++;
            }

            ptr = dash + 1;

            while (*ptr >= '0' && *ptr <= '9') {
                end_port = end_port * 10 + (*ptr - '0');
                ptr++;
            }

            if (start_port > 0 && end_port > 0 && start_port <= end_port && end_port <= 65535) {
                int range_count = end_port - start_port + 1;
                if (range_count > 1000) {
                    range_count = 1000;
                    end_port = start_port + 999;
                }

                for (int i = 0; i < range_count && port_index < *count; i++) {
                    ports[port_index++] = start_port + i;
                }
            }
        } else {
            int port = 0;
            char* ptr = token;
            while (*ptr >= '0' && *ptr <= '9') {
                port = port * 10 + (*ptr - '0');
                ptr++;
            }

            if (port > 0 && port <= 65535) {
                ports[port_index++] = port;
            }
        }

        token = MSVCRT$strtok(NULL, ",");
    }

    intFree(spec_copy);
    return ports;
}

void simple_port_scan(const char* target, int scan_level, const char* custom_ports)
{
    char** ip_list = NULL;
    int ip_count = 0;
    int* ports = NULL;
    int port_count = 0;
    int free_ports = 0;
    int need_cleanup_wsa = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting port scan for: %s\n", target);

    WSADATA wsa;
    if (WS2_32$WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "WSAStartup failed\n");
        return;
    }
    need_cleanup_wsa = 1;

    if (!parse_target_list_extended(target, &ip_list, &ip_count)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to parse targets: %s\n", target);
        goto cleanup;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d hosts\n", ip_count);

    if (scan_level == 0 && custom_ports && custom_ports[0]) {
        ports = parse_custom_ports(custom_ports, &port_count);
        if (ports) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using custom ports: %s (%d ports)\n", custom_ports, port_count);
            free_ports = 1;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Invalid custom port specification: %s\n", custom_ports);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using default port list instead\n");
            scan_level = 2;
        }
    }

    if (scan_level > 0) {
        switch (scan_level) {
            case 1:
                ports = g_level1_ports;
                for (port_count = 0; g_level1_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 1 scan: Web & Database ports (%d ports)\n", port_count);
                break;
            case 2:
                ports = g_level2_ports;
                for (port_count = 0; g_level2_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 2 scan: Web, Database & OS-specific ports (%d ports)\n", port_count);
                break;
            case 3:
                ports = g_level3_ports;
                for (port_count = 0; g_level3_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Level 3 scan: Comprehensive ports (%d ports)\n", port_count);
                break;
            default:
                ports = g_level2_ports;
                for (port_count = 0; g_level2_ports[port_count] != 0; port_count++);
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Default scan: Web, Database & OS-specific ports (%d ports)\n", port_count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %d ports\n", port_count);

    int total_open_ports = 0;
    for (int i = 0; i < ip_count; i++) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning %s...\n", ip_list[i]);

        int host_open_ports = 0;

        for (int batch_start = 0; batch_start < port_count; batch_start += SCAN_BATCH_SIZE) {
            int batch_end = batch_start + SCAN_BATCH_SIZE;
            if (batch_end > port_count) {
                batch_end = port_count;
            }

            for (int j = batch_start; j < batch_end; j++) {
                int port = ports[j];
                int state = tcp_port_scan(ip_list[i], port, DEFAULT_TIMEOUT);

                if (state > 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Port %d (%s) - OPEN\n",
                               port, get_service_name(port));
                    host_open_ports++;
                    total_open_ports++;
                }
            }

            if (batch_end < port_count) {
                KERNEL32$Sleep(BATCH_DELAY_MS);
            }
        }

        if (host_open_ports > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Host %s: %d open ports found\n",
                       ip_list[i], host_open_ports);
        }

        if (ip_count > 10 && (i + 1) % 10 == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Progress: %d/%d hosts scanned\n", i + 1, ip_count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scan completed. Found %d open ports total.\n", total_open_ports);

cleanup:
    if (ip_list) {
        for (int i = 0; i < ip_count; i++) {
            if (ip_list[i]) {
                intFree(ip_list[i]);
            }
        }
        intFree(ip_list);
        ip_list = NULL;
    }

    if (free_ports && ports) {
        intFree(ports);
        ports = NULL;
    }

    if (need_cleanup_wsa) {
        WS2_32$WSACleanup();
    }
}


int go(char* args, int len)
{
    char target[256] = {0};
    int scan_level = 2;
    char custom_ports[512] = {0};

    datap parser;
    BeaconDataParse(&parser, args, len);

    int target_size = 0;
    char* target_ptr = BeaconDataExtract(&parser, &target_size);
    if (target_ptr && target_size > 0) {
        MSVCRT$memcpy(target, target_ptr, target_size);
        target[target_size] = '\0';
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Parameters are not supported\n");
        return 0;
    }

    scan_level = BeaconDataInt(&parser);

    int ports_size = 0;
    char* ports_ptr = BeaconDataExtract(&parser, &ports_size);
    if (ports_ptr && ports_size > 0) {
        MSVCRT$memcpy(custom_ports, ports_ptr, ports_size);
        custom_ports[ports_size] = '\0';
    }

    simple_port_scan(target, scan_level, custom_ports);

    return 0;
}