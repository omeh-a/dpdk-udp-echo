#include <stdlib.h>
#include <stdio.h>

#define LWIP_DEBUG                              1
#define LWIP_STATS                              1
#define LWIP_DBG_MIN_LEVEL                      LWIP_DBG_LEVEL_ALL
// #define DHCP_DEBUG                              LWIP_DBG_ON
#define UDP_DEBUG                               LWIP_DBG_ON
#define ETHARP_DEBUG                            LWIP_DBG_ON
// #define IP_DEBUG                                LWIP_DBG_ON
// #define LWIP_NETIF_LINK_CALLBACK                1
#define LWIP_NETIF_STATUS_CALLBACK              1     
#define LWIP_UDP                                1
#define LWIP_ARP                                1
#define LWIP_DHCP                               1
#define DHCP_DOES_ARP_CHECK                     1
#define DHCP_COARSE_TIMER_SECS                  60
#define DHCP_FINE_TIMER_MSECS                   500
#define ETHARP_SUPPORT_STATIC_ENTRIES           1
#define LWIP_IPV4                               1
// #define LWIP_IPV6                               1
/* Leave the checksum checking on RX to hardware */
#define CHECKSUM_CHECK_IP                       0
#define CHECKSUM_CHECK_UDP                      0
#define CHECKSUM_CHECK_TCP                      0
#define CHECKSUM_CHECK_ICMP                     0
#define CHECKSUM_CHECK_ICMP6                    0
// #define ETHARP_SUPPORT_STATIC_ENTRIES        1
// #define LWIP_STATS                           1
#define ETHARP_STATS                            1
#define ARP_MAXAGE                           300
#define ARP_MAXPENDING                          30
#define ARP_TMR_INTERVAL                     1000
#define ARP_QUEUING                             1
#define ARP_QUEUE_LEN                           30
#define ARP_TABLE_SIZE                       50
