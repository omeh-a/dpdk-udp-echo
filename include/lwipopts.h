// lwipopts.h
// This file overrides the default configuration in LWIP so it does
// something sane. You may need to change some elements for your system
// but it is unlikely. Define DEBUG_LWIP to 1 to turn on all LWIP debug
// output.

#include <stdlib.h>
#include <stdio.h>

#define DEBUG_LWIP 0

#define NO_SYS                                  1

#define LWIP_TIMERS                             1
#define LWIP_NETCONN                            0
#define LWIP_SOCKET                             0
#define LWIP_ICMP                               1
#define LWIP_RAND                               rand
#define LWIP_DHCP                               1

#define MEM_ALIGNMENT                           4
#define MEM_SIZE                                0x4000

#define ETHARP_SUPPORT_STATIC_ENTRIES           1
#define SYS_LIGHTWEIGHT_PROT                    0
#define LWIP_NETIF_STATUS_CALLBACK              1

/* Leave the checksum checking on RX to hardware */
#define CHECKSUM_GEN_UDP                        0

#define CHECKSUM_CHECK_IP                       0
#define CHECKSUM_CHECK_UDP                      0
#define CHECKSUM_CHECK_TCP                      0
#define CHECKSUM_CHECK_ICMP                     0
#define CHECKSUM_CHECK_ICMP6                    0

//#define ETHARP_STATS                            1
//#define ARP_MAXAGE                              300
//#define ARP_MAXPENDING                          30
//#define ARP_TMR_INTERVAL                        1000
//#define ARP_QUEUEING                            0
//#define ARP_QUEUE_LEN                           30
//#define ARP_TABLE_SIZE                          50

#define TCP_SND_QUEUELEN 2500
#define MEMP_NUM_TCP_SEG TCP_SND_QUEUELEN
#define TCP_SND_BUF (100 * TCP_MSS)
#define TCP_WND (100 * TCP_MSS)
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 10
#define PBUF_POOL_SIZE 1000
#define MEMP_NUM_SYS_TIMEOUT 512

// ### DEBUG ###

#if DEBUG_LWIP == 1
#define LWIP_STATS                              1
#define LWIP_DEBUG                              1
#define LWIP_DBG_MIN_LEVEL                      LWIP_DBG_LEVEL_ALL
#define DHCP_DEBUG                              LWIP_DBG_ON
#define UDP_DEBUG                               LWIP_DBG_ON
#define ETHARP_DEBUG                            LWIP_DBG_ON
#define IP_DEBUG                                LWIP_DBG_ON
#endif