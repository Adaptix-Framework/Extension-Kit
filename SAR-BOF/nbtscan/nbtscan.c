#include "nbtscan.h"

void bofstart() {}
void bofstop() {}

static unsigned int nbtscan_strlen(const char *s) {
    return (unsigned int)MSVCRT$strlen(s);
}

static void nbtscan_strcpy(char *dst, const char *src) {
    MSVCRT$strcpy(dst, src);
}

static char *nbtscan_strchr(char *s, int c) {
    return MSVCRT$strchr(s, c);
}

static unsigned long nbtscan_strtoul(const char *s) {
    return MSVCRT$strtoul(s, NULL, 10);
}

static char nbtscan_upper(char c) {
    if (c >= 'a' && c <= 'z') {
        return (char)(c - 'a' + 'A');
    }
    return c;
}

static my_uint16_t nbtscan_get16(const unsigned char *data) {
    return (my_uint16_t)((data[0] << 8) | data[1]);
}

static my_uint32_t nbtscan_get32(const unsigned char *data) {
    return ((my_uint32_t)data[0] << 24) |
           ((my_uint32_t)data[1] << 16) |
           ((my_uint32_t)data[2] << 8)  |
           (my_uint32_t)data[3];
}

static int nbtscan_is_ip(const char *s, ip_range32_t *range) {
    unsigned long addr = WS2_32$inet_addr(s);
    if (addr == 0xFFFFFFFFUL) {
        return 0;
    }
    my_uint32_t h = WS2_32$ntohl(addr);
    range->start_ip = h;
    range->end_ip   = h;
    return 1;
}

static int nbtscan_is_range_dash(char *s, ip_range32_t *range) {
    char *dash = nbtscan_strchr(s, '-');
    if (!dash) return 0;

    *dash = '\0';
    char *first = s;
    char *second = dash + 1;

    unsigned long addr1 = WS2_32$inet_addr(first);
    if (addr1 == 0xFFFFFFFFUL) {
        return 0;
    }
    my_uint32_t start_h = WS2_32$ntohl(addr1);

    if (nbtscan_strchr(second, '.') != NULL) {
        unsigned long addr2 = WS2_32$inet_addr(second);
        if (addr2 == 0xFFFFFFFFUL) {
            return 0;
        }
        my_uint32_t end_h = WS2_32$ntohl(addr2);
        if (end_h < start_h) return 0;
        range->start_ip = start_h;
        range->end_ip   = end_h;
        return 1;
    }

    unsigned long last_octet = nbtscan_strtoul(second);
    if (last_octet > 255) return 0;

    my_uint32_t end_h = (start_h & 0xFFFFFF00UL) | last_octet;
    if (end_h < start_h) return 0;
    range->start_ip = start_h;
    range->end_ip   = end_h;
    return 1;
}

static int nbtscan_is_cidr(char *s, ip_range32_t *range) {
    char *slash = nbtscan_strchr(s, '/');
    if (!slash) return 0;

    *slash = '\0';
    char *ip_part = s;
    char *mask_part = slash + 1;

    unsigned long addr = WS2_32$inet_addr(ip_part);
    if (addr == 0xFFFFFFFFUL) {
        return 0;
    }
    unsigned long mask_bits = nbtscan_strtoul(mask_part);
    if (mask_bits == 0 || mask_bits > 32) {
        return 0;
    }

    my_uint32_t h = WS2_32$ntohl(addr);
    my_uint32_t mask32;
    if (mask_bits == 32) {
        mask32 = 0xFFFFFFFFUL;
    } else {
        mask32 = ((1UL << mask_bits) - 1UL) << (32 - mask_bits);
    }
    my_uint32_t start = h & mask32;
    my_uint32_t end   = start | ~mask32;

    range->start_ip = start;
    range->end_ip   = end;
    return 1;
}

static int nbtscan_expand_range(const ip_range32_t *range, char ***out_list, int *out_count, int *total_ips) {
    my_uint32_t count = (range->end_ip >= range->start_ip)
                        ? (range->end_ip - range->start_ip + 1)
                        : 0;
    if (count == 0) return 0;

    if (*total_ips + (int)count > NBTS_MAX_IPS) {
        count = NBTS_MAX_IPS - *total_ips;
    }
    if (count == 0) return 0;

    int new_total = *total_ips + (int)count;
    char **new_list = (char**)intRealloc(*out_list, new_total * sizeof(char*));
    if (!new_list) {
        return 0;
    }
    *out_list = new_list;

    for (my_uint32_t i = 0; i < count; i++) {
        my_uint32_t ip_h = range->start_ip + i;
        struct in_addr a;
        a.s_addr = WS2_32$htonl(ip_h);
        char *s = WS2_32$inet_ntoa(a);
        if (!s) continue;

        char *dst = (char*)intAlloc(16);
        if (!dst) continue;
        nbtscan_strcpy(dst, s);
        (*out_list)[*total_ips + (int)i] = dst;
    }
    *out_count = new_total;
    *total_ips = new_total;
    return 1;
}

static int nbtscan_parse_targets(const char *targets, char ***out_list, int *out_count) {
    *out_list = NULL;
    *out_count = 0;
    if (!targets || !targets[0]) return 0;

    unsigned int len = nbtscan_strlen(targets);
    char *copy = (char*)intAlloc(len + 1);
    if (!copy) return 0;
    nbtscan_strcpy(copy, targets);

    char **result = NULL;
    int total = 0;

    char *ctx = NULL;
    char *token = MSVCRT$strtok_s(copy, ",", &ctx);
    while (token && total < NBTS_MAX_IPS) {
        while (*token == ' ' || *token == '\t') token++;

        char *end = token + nbtscan_strlen(token);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
            *--end = '\0';
        }

        ip_range32_t range;
        int is_range = 0;

        char *work = (char*)intAlloc(nbtscan_strlen(token) + 1);
        if (!work) {
            break;
        }
        nbtscan_strcpy(work, token);

        if (nbtscan_is_cidr(work, &range)) {
            is_range = 1;
        } else {
            nbtscan_strcpy(work, token);
            if (nbtscan_is_range_dash(work, &range)) {
                is_range = 1;
            } else {
                nbtscan_strcpy(work, token);
                if (nbtscan_is_ip(work, &range)) {
                    is_range = 1;
                }
            }
        }

        if (is_range) {
            nbtscan_expand_range(&range, &result, &total, &total);
        }

        intFree(work);
        token = MSVCRT$strtok_s(NULL, ",", &ctx);
    }

    intFree(copy);
    *out_list = result;
    *out_count = total;
    return (total > 0);
}

static void nbtscan_free_targets(char **list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        if (list[i]) {
            intFree(list[i]);
        }
    }
    intFree(list);
}

static void nbtscan_name_mangle_star(char *out_name) {
    char buf[16];
    MSVCRT$memset(buf, 0, sizeof(buf));
    buf[0] = '*';

    char *p = out_name;
    p[0] = 32;
    p++;

    for (int i = 0; i < 16; i++) {
        int c = (unsigned char)nbtscan_upper(buf[i]);
        p[2 * i]     = (char)(((c >> 4) & 0x0F) + 'A');
        p[2 * i + 1] = (char)((c & 0x0F) + 'A');
    }
    p[32] = 0;
}

static int nbtscan_send_query(SOCKET sock, struct in_addr addr, my_uint16_t tid) {
    nbname_request_t req;
    MSVCRT$memset(&req, 0, sizeof(req));

    req.transaction_id          = WS2_32$htons(tid);
    req.flags                   = WS2_32$htons(0x0010);
    req.question_count          = WS2_32$htons(1);
    req.answer_count            = 0;
    req.name_service_count      = 0;
    req.additional_record_count = 0;

    nbtscan_name_mangle_star(req.question_name);
    req.question_type  = WS2_32$htons(NBNAME_QUESTION_TYPE);
    req.question_class = WS2_32$htons(NBNAME_QUESTION_CLASS);

    struct sockaddr_in dst;
    MSVCRT$memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = WS2_32$htons(NB_DGRAM);
    dst.sin_addr   = addr;

    int status = WS2_32$sendto(sock, (char*)&req, sizeof(req), 0, (struct sockaddr*)&dst, sizeof(dst));
    return (status >= 0);
}

static int nbtscan_parse_response(unsigned char *buff, int buffsize, nb_host_info_t *out) {
    if (!buff || buffsize < 0) return 0;
    MSVCRT$memset(out, 0, sizeof(*out));

    int offset = 0;

    if (buffsize < 57) {
        return 0;
    }

    nbname_response_header_t *hdr = (nbname_response_header_t*)intAlloc(sizeof(nbname_response_header_t));
    if (!hdr) return 0;

    hdr->transaction_id          = nbtscan_get16(buff + offset); offset += 2;
    hdr->flags                   = nbtscan_get16(buff + offset); offset += 2;
    hdr->question_count          = nbtscan_get16(buff + offset); offset += 2;
    hdr->answer_count            = nbtscan_get16(buff + offset); offset += 2;
    hdr->name_service_count      = nbtscan_get16(buff + offset); offset += 2;
    hdr->additional_record_count = nbtscan_get16(buff + offset); offset += 2;

    if (offset + 34 > buffsize) {
        intFree(hdr);
        return 0;
    }
    MSVCRT$memcpy(hdr->question_name, buff + offset, 34);
    offset += 34;

    if (offset + 2 > buffsize) { intFree(hdr); return 0; }
    hdr->question_type = nbtscan_get16(buff + offset); offset += 2;
    if (offset + 2 > buffsize) { intFree(hdr); return 0; }
    hdr->question_class = nbtscan_get16(buff + offset); offset += 2;

    if (offset + 4 > buffsize) { intFree(hdr); return 0; }
    hdr->ttl = nbtscan_get32(buff + offset); offset += 4;

    if (offset + 2 > buffsize) { intFree(hdr); return 0; }
    hdr->rdata_length = nbtscan_get16(buff + offset); offset += 2;

    if (offset + 1 > buffsize) { intFree(hdr); return 0; }
    hdr->number_of_names = buff[offset]; offset += 1;

    out->header = hdr;

    int name_count = hdr->number_of_names;
    int table_size = name_count * (int)sizeof(nbname_t);
    if (table_size > 0) {
        if (offset + table_size > buffsize) {
            return 1;
        }

        nbname_t *names = (nbname_t*)intAlloc(table_size);
        if (!names) {
            return 1;
        }
        for (int i = 0; i < name_count; i++) {
            MSVCRT$memcpy(names[i].ascii_name, buff + offset, 16);
            offset += 16;
            if (offset + 2 > buffsize) {
                return 1;
            }
            names[i].rr_flags = nbtscan_get16(buff + offset);
            offset += 2;
        }
        out->names = names;
    }

    if (offset + 6 > buffsize) {
        return 1;
    }

    nbname_response_footer_t *foot = (nbname_response_footer_t*)intAlloc(sizeof(nbname_response_footer_t));
    if (!foot) {
        return 1;
    }
    MSVCRT$memset(foot, 0, sizeof(*foot));

    MSVCRT$memcpy(foot->adapter_address, buff + offset, 6);
    offset += 6;

    out->footer = foot;
    return 1;
}

static void nbtscan_free_hostinfo(nb_host_info_t *info) {
    if (!info) return;
    if (info->header) intFree(info->header);
    if (info->names)  intFree(info->names);
    if (info->footer) intFree(info->footer);
    MSVCRT$memset(info, 0, sizeof(*info));
}

static void nbtscan_print_header(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "%-17s%-17s%-17s%-10s%-17s%-17s",
                 "IP address",
                 "NetBIOS Name",
                 "Domain/Workgroup",
                 "Server",
                 "User",
                 "MAC address");
}

static void nbtscan_pick_names(const nb_host_info_t *info,
                               char *comp_name,
                               char *user_name,
                               char *domain_name,
                               int *is_server,
                               int *is_domain) {
    comp_name[0] = '\0';
    user_name[0] = '\0';
    if (domain_name) domain_name[0] = '\0';
    *is_server = 0;
    if (is_domain) *is_domain = 0;

    if (!info->header || !info->names) return;

    int first_name = 1;
    for (int i = 0; i < info->header->number_of_names; i++) {
        unsigned char service = (unsigned char)info->names[i].ascii_name[15];
        int unique = !(info->names[i].rr_flags & 0x8000);

        if (service == 0x00 && unique && first_name) {
            MSVCRT$memcpy(comp_name, info->names[i].ascii_name, 15);
            comp_name[15] = 0;
            first_name = 0;
        }
        if (service == 0x00 && !unique && domain_name && !domain_name[0]) {
            MSVCRT$memcpy(domain_name, info->names[i].ascii_name, 15);
            domain_name[15] = 0;
            int len = MSVCRT$strlen(domain_name);
            while (len > 0 && domain_name[len - 1] == ' ') {
                domain_name[len - 1] = '\0';
                len--;
            }
        }
        if (is_domain && (service == 0x1B || service == 0x1C)) {
            *is_domain = 1;
        }
        if (service == 0x20 && unique) {
            *is_server = 1;
        }
        if (service == 0x03 && unique) {
            MSVCRT$memcpy(user_name, info->names[i].ascii_name, 15);
            user_name[15] = 0;
        }
    }
    
    if (is_domain && domain_name && domain_name[0] && *is_domain == 0) {
        const char *workgroup_names[] = {
            "WORKGROUP",
            "MSHOME",
            "HOME",
            NULL
        };
        
        int is_standard_workgroup = 0;
        for (int i = 0; workgroup_names[i] != NULL; i++) {
            int j = 0;
            int match = 1;
            while (domain_name[j] != '\0' && workgroup_names[i][j] != '\0') {
                char c1 = nbtscan_upper(domain_name[j]);
                char c2 = nbtscan_upper(workgroup_names[i][j]);
                if (c1 != c2) {
                    match = 0;
                    break;
                }
                j++;
            }
            if (match && domain_name[j] == '\0' && workgroup_names[i][j] == '\0') {
                is_standard_workgroup = 1;
                break;
            }
        }
        
        if (!is_standard_workgroup) {
            int len = MSVCRT$strlen(domain_name);
            if (len >= 4) {
                char prefix[5] = {0};
                MSVCRT$memcpy(prefix, domain_name, 4);
                prefix[0] = nbtscan_upper(prefix[0]);
                prefix[1] = nbtscan_upper(prefix[1]);
                prefix[2] = nbtscan_upper(prefix[2]);
                prefix[3] = nbtscan_upper(prefix[3]);
                if (MSVCRT$strcmp(prefix, "HOME") == 0) {
                    int all_digits = 1;
                    for (int k = 4; k < len; k++) {
                        if (domain_name[k] < '0' || domain_name[k] > '9') {
                            all_digits = 0;
                            break;
                        }
                    }
                    if (all_digits) {
                        is_standard_workgroup = 1;
                    }
                }
            }
        }
        
        if (!is_standard_workgroup) {
            *is_domain = 1;
        }
    }
}

static void nbtscan_print_hostinfo_normal(const char *ip, const nb_host_info_t *info) {
    char comp_name[16];
    char user_name[16];
    char domain_name[16];
    int is_server = 0;

    nbtscan_pick_names(info, comp_name, user_name, domain_name, &is_server, NULL);
    if (!comp_name[0]) nbtscan_strcpy(comp_name, "<unknown>");
    if (!user_name[0]) nbtscan_strcpy(user_name, "<unknown>");
    if (!domain_name[0]) nbtscan_strcpy(domain_name, "<unknown>");

    if (info->footer) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "%-17s%-17s%-17s%-10s%-17s%02x:%02x:%02x:%02x:%02x:%02x",
                     ip,
                     comp_name,
                     domain_name,
                     is_server ? "<server>" : "",
                     user_name,
                     info->footer->adapter_address[0],
                     info->footer->adapter_address[1],
                     info->footer->adapter_address[2],
                     info->footer->adapter_address[3],
                     info->footer->adapter_address[4],
                     info->footer->adapter_address[5]);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "%-17s%-17s%-17s%-10s%-17s",
                     ip,
                     comp_name,
                     domain_name,
                     is_server ? "<server>" : "",
                     user_name);
    }
}

static void nbtscan_print_hostinfo_verbose(const char *ip,
                                           const nb_host_info_t *info,
                                           const char *sep,
                                           int script_mode) {
    if (!info->header || !info->names) return;

    if (!script_mode) {
        BeaconPrintf(CALLBACK_OUTPUT, "\nNetBIOS Name Table for Host %s:\n", ip);
    }

    for (int i = 0; i < info->header->number_of_names; i++) {
        char name[16];
        MSVCRT$memcpy(name, info->names[i].ascii_name, 15);
        name[15] = 0;
        unsigned char service = (unsigned char)info->names[i].ascii_name[15];
        int unique = !(info->names[i].rr_flags & 0x8000);

        if (script_mode) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "%s%s%s%s%02x%s%s",
                         ip,
                         sep,
                         name,
                         sep,
                         service,
                         sep,
                         unique ? "U" : "G");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "%-17s<%02x>%s",
                         name,
                         service,
                         unique ? " UNIQUE" : " GROUP");
        }
    }

    if (!script_mode && info->footer) {
        BeaconPrintf(CALLBACK_OUTPUT,
                     "Adapter address: %02x:%02x:%02x:%02x:%02x:%02x",
                     info->footer->adapter_address[0],
                     info->footer->adapter_address[1],
                     info->footer->adapter_address[2],
                     info->footer->adapter_address[3],
                     info->footer->adapter_address[4],
                     info->footer->adapter_address[5]);
    }
}

static void nbtscan_print_hostinfo_hosts(const char *ip,
                                         const nb_host_info_t *info,
                                         int lmhosts) {
    char comp_name[16];
    char dummy_user[16];
    int dummy_server = 0;

    nbtscan_pick_names(info, comp_name, dummy_user, NULL, &dummy_server, NULL);
    if (!comp_name[0]) nbtscan_strcpy(comp_name, "<unknown>");

    if (lmhosts) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\t%s\t#PRE", ip, comp_name);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "%s\t%s", ip, comp_name);
    }
}

static void nbtscan_emit_ax_target(const char *ip, const nb_host_info_t *info, const char *tag) {
    if (!ip || !info) return;

    char comp_name[16];
    char user_name[16];
    char domain_name[16];
    int dummy_server = 0;
    int is_domain = 0;

    nbtscan_pick_names(info, comp_name, user_name, domain_name, &dummy_server, &is_domain);
    if (!comp_name[0]) nbtscan_strcpy(comp_name, "<unknown>");
    if (!user_name[0]) nbtscan_strcpy(user_name, "<unknown>");

    char info_buf[128] = {0};
    MSVCRT$strcpy(info_buf, "nbtscan");
    if (user_name[0] && MSVCRT$strcmp(user_name, "<unknown>") != 0) {
        MSVCRT$strcat(info_buf, ", user=");
        MSVCRT$strcat(info_buf, user_name);
    }

    const char *tag_str = (tag && tag[0]) ? tag : "";

    char domain_final[64] = {0};
    if (domain_name[0] && MSVCRT$strcmp(domain_name, "<unknown>") != 0) {
        if (nbtscan_strchr(domain_name, '.') == NULL) {
            if (is_domain) {
                MSVCRT$strcpy(domain_final, domain_name);
                MSVCRT$strcat(domain_final, ".local");
            } else {
                MSVCRT$strcpy(domain_final, domain_name);
            }
        } else {
            MSVCRT$strcpy(domain_final, domain_name);
        }
    }

    AxAddTarget(
        comp_name[0] ? comp_name : "",
        domain_final[0] ? domain_final : "",
        (char*)ip,
        0,
        "",
        (char*)tag_str,
        info_buf,
        1
    );
}

void go(char *args, int alen) {
    datap parser;
    char *targets = NULL;
    int verbose = 0;
    int quiet = 0;
    int etc_hosts = 0;
    int lmhosts = 0;
    char *sep = NULL;
    int timeout_ms = 1000;
    char *tag = NULL;
    int no_targets = 0;

    BeaconDataParse(&parser, args, alen);
    targets    = (char*)BeaconDataExtract(&parser, NULL);
    verbose    = BeaconDataInt(&parser);
    quiet      = BeaconDataInt(&parser);
    etc_hosts  = BeaconDataInt(&parser);
    lmhosts    = BeaconDataInt(&parser);
    sep        = (char*)BeaconDataExtract(&parser, NULL);
    timeout_ms = BeaconDataInt(&parser);
    tag        = (char*)BeaconDataExtract(&parser, NULL);
    no_targets = BeaconDataInt(&parser);

    if (!targets || !targets[0]) {
        BeaconPrintf(CALLBACK_ERROR, "nbtscan: no targets specified");
        return;
    }

    if (timeout_ms <= 0) timeout_ms = 1000;

    WSADATA wsa;
    if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "nbtscan: WSAStartup failed");
        return;
    }

    SOCKET sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_ERROR, "nbtscan: socket() failed");
        WS2_32$WSACleanup();
        return;
    }

    char **ip_list = NULL;
    int ip_count = 0;
    if (!nbtscan_parse_targets(targets, &ip_list, &ip_count) || ip_count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "nbtscan: invalid targets string");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }

    int script_mode = 0;
    const char *script_sep = ",";
    if (sep && sep[0]) {
        script_mode = (!etc_hosts && !lmhosts);
        script_sep = sep;
    }

    if (!etc_hosts && !lmhosts && !script_mode && !quiet) {
        nbtscan_print_header();
    }

    struct in_addr *ip_addrs = (struct in_addr*)intAlloc(ip_count * sizeof(struct in_addr));
    unsigned char *seen = (unsigned char*)intAlloc(ip_count);
    if (!ip_addrs || !seen) {
        BeaconPrintf(CALLBACK_ERROR, "nbtscan: memory allocation failed");
        if (ip_addrs) intFree(ip_addrs);
        if (seen) intFree(seen);
        nbtscan_free_targets(ip_list, ip_count);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return;
    }
    MSVCRT$memset(seen, 0, ip_count);

    my_uint16_t tid = 1;

    for (int i = 0; i < ip_count; i++) {
        unsigned long raw = WS2_32$inet_addr(ip_list[i]);
        if (raw == 0xFFFFFFFFUL) {
            if (!quiet) {
                BeaconPrintf(CALLBACK_ERROR, "nbtscan: invalid IP %s", ip_list[i]);
            }
            ip_addrs[i].s_addr = 0;
            continue;
        }

        ip_addrs[i].s_addr = raw;

        if (!nbtscan_send_query(sock, ip_addrs[i], tid++)) {
            if (!quiet) {
                BeaconPrintf(CALLBACK_ERROR, "nbtscan: failed to send to %s", ip_list[i]);
            }
            continue;
        }
    }

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = WS2_32$select((int)(sock + 1), &rfds, NULL, NULL, &tv);
        if (sel <= 0) {
            break;
        }

        unsigned char buff[1024];
        struct sockaddr_in src;
        int slen = sizeof(src);
        int n = WS2_32$recvfrom(sock, (char*)buff, sizeof(buff), 0, (struct sockaddr*)&src, &slen);
        if (n <= 0) {
            continue;
        }

        const char *ip_str = NULL;
        int idx = -1;
        for (int i = 0; i < ip_count; i++) {
            if (ip_addrs[i].s_addr != 0 && ip_addrs[i].s_addr == src.sin_addr.s_addr) {
                idx = i;
                ip_str = ip_list[i];
                break;
            }
        }

        if (!ip_str) {
            ip_str = WS2_32$inet_ntoa(src.sin_addr);
        } else if (idx >= 0 && seen[idx]) {
            continue;
        }

        if (idx >= 0) {
            seen[idx] = 1;
        }

        nb_host_info_t info;
        MSVCRT$memset(&info, 0, sizeof(info));
        if (!nbtscan_parse_response(buff, n, &info)) {
            if (!quiet && ip_str) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s\tinvalid NBSTAT response", ip_str);
            }
            nbtscan_free_hostinfo(&info);
            continue;
        }

        if (etc_hosts || lmhosts) {
            nbtscan_print_hostinfo_hosts(ip_str, &info, lmhosts);
        } else if (script_mode) {
            nbtscan_print_hostinfo_verbose(ip_str, &info, script_sep, 1);
        } else if (verbose) {
            nbtscan_print_hostinfo_normal(ip_str, &info);
            nbtscan_print_hostinfo_verbose(ip_str, &info, script_sep, 0);
        } else {
            nbtscan_print_hostinfo_normal(ip_str, &info);
        }

        if (!no_targets) {
            nbtscan_emit_ax_target(ip_str, &info, tag);
        }

        nbtscan_free_hostinfo(&info);
    }

    if (ip_addrs) intFree(ip_addrs);
    if (seen) intFree(seen);
    nbtscan_free_targets(ip_list, ip_count);
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();
}

