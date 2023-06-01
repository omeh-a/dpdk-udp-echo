#include <lwip/opt.h>
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

#include <lwip/etharp.h>

#include <netif/ethernet.h>
#include "udpecho.h"

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

err_t dhcp_setup(struct netif netif)
{
    netif_set_status_callback(&netif, netif_status_callback);
    netif_set_up(&netif);
    printf("## DHCP SETUP ## \n");
    
    if(!netif_is_up(&netif)) {
        printf("WARNING: network interface not active.\n");
    } else {
        printf("Network interface is active.\n");
    }
    return dhcp_start(&netif);
}

