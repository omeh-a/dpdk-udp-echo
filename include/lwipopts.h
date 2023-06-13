#include <stdlib.h>
#include <stdio.h>

#define LWIP_DEBUG                            1
#define LWIP_STATS                              1
#define LWIP_DBG_MIN_LEVEL                   LWIP_DBG_LEVEL_ALL
#define DHCP_DEBUG                           LWIP_DBG_ON
#define UDP_DEBUG                            LWIP_DBG_ON
#define ETHARP_DEBUG                         LWIP_DBG_ON
// #define PBUF_DEBUG                           LWIP_DBG_ON
#define IP_DEBUG                             LWIP_DBG_ON
// #define TCPIP_DEBUG                          LWIP_DBG_ON
// #define DHCP_DEBUG                           LWIP_DBG_ON
#define LWIP_NETIF_LINK_CALLBACK             1
#define LWIP_NETIF_STATUS_CALLBACK           1     
#define LWIP_UDP                             1
#define LWIP_ARP                            1
#define ETHARP_SUPPORT_STATIC_ENTRIES   1
#define LWIP_RAND                       rand

/* Leave the checksum checking on RX to hardware */
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_CHECK_ICMP             0
#define CHECKSUM_CHECK_ICMP6            0
#define LWIP_DHCP                            1
// #define ETHARP_SUPPORT_STATIC_ENTRIES        1
// #define LWIP_STATS                           1
// #define ETHARP_STATS                         1
// #define ARP_MAXAGE                           300
// #define ARP_MAXPENDING                       30
// #define ARP_TMR_INTERVAL                     1000
#define ARP_QUEUING                          1
#define ARP_QUEUE_LEN                        30
// #define ARP_TABLE_SIZE                       50
