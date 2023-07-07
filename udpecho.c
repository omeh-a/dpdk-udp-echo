/*
 * Copyright 2023, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

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

