#ifndef NBTSCAN_H
#define NBTSCAN_H

#include <Winsock2.h>
#include <Windows.h>

#include "../_include/beacon.h"
#include "../_include/bofdefs.h"
#include "../_include/adaptix.h"

__declspec(dllimport) unsigned long __stdcall WS2_32$inet_addr(const char *cp);
__declspec(dllimport) unsigned short __stdcall WS2_32$htons(unsigned short hostshort);
__declspec(dllimport) unsigned long __stdcall WS2_32$ntohl(unsigned long netlong);
DECLSPEC_IMPORT unsigned int __stdcall WS2_32$socket(int af, int type, int protocol);
__declspec(dllimport) int __stdcall WS2_32$closesocket(SOCKET);
__declspec(dllimport) int __stdcall WS2_32$sendto(SOCKET, const char*, int, int, const struct sockaddr*, int);
__declspec(dllimport) int __stdcall WS2_32$recvfrom(SOCKET, char*, int, int, struct sockaddr*, int*);
__declspec(dllimport) int __stdcall WS2_32$select(int, fd_set*, fd_set*, fd_set*, const struct timeval*);
__declspec(dllimport) int __stdcall WS2_32$WSAStartup(WORD, LPWSADATA);
__declspec(dllimport) int __stdcall WS2_32$WSACleanup(void);
__declspec(dllimport) char* __stdcall WS2_32$inet_ntoa(struct in_addr);

#define NB_DGRAM                137
#define NBNAME_QUESTION_TYPE    0x21
#define NBNAME_QUESTION_CLASS   0x01

typedef unsigned __int8  my_uint8_t;
typedef unsigned __int16 my_uint16_t;
typedef unsigned __int32 my_uint32_t;

typedef struct _nbname {
    char        ascii_name[16];
    my_uint16_t rr_flags;
} nbname_t;

typedef struct _nbname_response_header {
    my_uint16_t transaction_id;
    my_uint16_t flags;
    my_uint16_t question_count;
    my_uint16_t answer_count;
    my_uint16_t name_service_count;
    my_uint16_t additional_record_count;
    char        question_name[34];
    my_uint16_t question_type;
    my_uint16_t question_class;
    my_uint32_t ttl;
    my_uint16_t rdata_length;
    my_uint8_t  number_of_names;
} nbname_response_header_t;

typedef struct _nbname_response_footer {
    my_uint8_t  adapter_address[6];
} nbname_response_footer_t;

typedef struct _nb_host_info {
    nbname_response_header_t *header;
    nbname_t                 *names;
    nbname_response_footer_t *footer;
} nb_host_info_t;

typedef struct _nbname_request {
    my_uint16_t transaction_id;
    my_uint16_t flags;
    my_uint16_t question_count;
    my_uint16_t answer_count;
    my_uint16_t name_service_count;
    my_uint16_t additional_record_count;
    char        question_name[34];
    my_uint16_t question_type;
    my_uint16_t question_class;
} nbname_request_t;

#define NBTS_MAX_IPS  8192

typedef struct _ip_range32 {
    my_uint32_t start_ip;
    my_uint32_t end_ip;
} ip_range32_t;

#endif
