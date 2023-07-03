#include "lwipopts.h"
#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <lwip/tcpip.h>
#include <lwip/timeouts.h>
#include <lwip/prot/tcp.h>
#include "lwip/api.h"
#include "lwip/sys.h"
#include <lwip/dhcp.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_bus_pci.h>

#include <lwip/etharp.h>

#include <netif/ethernet.h>
#include "udpecho.h"
#include "pthread.h"

/**
 * @brief Callback function for network interface status change
 * 
 * @param netif 
 */
static void netif_status_callback(struct netif *netif) {
    printf("NETIF STATUS CHANGE\n");
    if (dhcp_supplied_address(netif)) {
        printf("DHCP request finished, IP address for netif ");
        printf("%s", netif->name);
        printf(" is: ");
        printf("%s\n",ip4addr_ntoa(netif_ip4_addr(netif)));
    }

}

err_t dhcp_setup(struct netif *netif)
{
    netif_set_status_callback(netif, netif_status_callback);
    netif_set_up(netif);
    printf("## DHCP SETUP ## \n");
    
    if(!netif_is_up(netif)) {
        printf("WARNING: network interface not active.\n");
    } else {
        printf("Network interface is active.\n");
    }

    // Wait for NIC to find link
    struct rte_eth_link link;
    rte_eth_link_get_nowait(0, &link);
    while (!link.link_status) {
        rte_eth_link_get_nowait(0, &link);
        if (link.link_status) {
            printf("Link is up.\n");
        } else {
            printf("Link is down.\n");
        }
        usleep(ARP_TMR_INTERVAL * 1000);
    }
    return dhcp_start(netif);
}

int dhcp_addr_supplied(struct netif *netif) {
    return dhcp_supplied_address(netif);
}

