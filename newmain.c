/*
 * Copyright 2023, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */
// DPDK echo server - single-threaded over LWIP
// Matt Rossouw (omeh-a)
// 07/2023

// Uncomment below for debugging output
// #define DEBUG

#include "main.h"

static struct rte_mempool *pktmbuf_pool = NULL;
static int mbuf_count = 0;
static struct rte_mbuf *tx_mbuf = {0};

static uint8_t _mac[6];

static inline void *lwip_timeouts_thread(void *arg __attribute__((unused)))
{
    for (;;)
    {
        sys_check_timeouts();
        usleep(ARP_TMR_INTERVAL * 1000);
    }
    return NULL;
}

// Custom pbuf for zero copy between DPDK/LWIP
typedef struct lwip_custom_pbuf {
    struct pbuf_custom pbuf;
    struct rte_mbuf *mbuf;
} lwip_custom_pbuf_t;

LWIP_MEMPOOL_DECLARE(
    RX_POOL,
    PACKET_BUF_SIZE * 2,
    sizeof(lwip_custom_pbuf_t),
    "Zero-copy RX pool"
);

// Custom pbuf handling functions
static void free_custom_pbuf(struct pbuf *p)
{
    lwip_custom_pbuf_t *pk = (lwip_custom_pbuf_t *)p;
    rte_pktmbuf_free(pk->mbuf);
    LWIP_MEMPOOL_FREE(RX_POOL, pk);
}

static struct pbuf *alloc_custom_pbuf(struct rte_mbuf *mbuf)
{
    lwip_custom_pbuf_t *pk = (lwip_custom_pbuf_t *)LWIP_MEMPOOL_ALLOC(RX_POOL);
    assert(pk != NULL && "Failed to allocate custom pbuf!");
    pk->mbuf = mbuf;
    pk->pbuf.custom_free_function = free_custom_pbuf;
    return pbuf_alloced_custom(
        PBUF_RAW,
        &pk->mbuf->pkt_len, // Might need to make this bigger
        PBUF_REF,
        &pk->pbuf,
        rte_pktmbuf_mtod(pk->mbuf, void *),
        &pk->mbuf->pkt_len
    );
}

// Function to output packets for lwip
/**
 * @brief Output function for lwip
 * @warning Frees supplied pbuf after sending, including releasing the underlying DPDK mbuf
*/
static err_t tx_output(struct netif *netif __attribute__((unused)), struct pbuf *p)
{
    
    // Copy pbuf data to mbuf
    char buf[PACKET_BUF_SIZE];
    void *bufptr, *largebuf = NULL;
    if (sizeof(buf) < p->tot_len)
    {
        largebuf = (char *)malloc(p->tot_len);
        assert(largebuf);
        bufptr = largebuf;
    }
    else
    {
        bufptr = buf;
        largebuf = NULL;
    }
    pbuf_copy_partial(p, bufptr, p->tot_len, 0);

    const uint32_t offloads = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
    tx_mbuf = rte_pktmbuf_alloc(pktmbuf_pool);
    tx_mbuf->ol_flags |= offloads;
    tx_mbuf->l2_len = sizeof(struct rte_ether_hdr);
    tx_mbuf->l3_len = sizeof(struct rte_ipv4_hdr);

    // Generate checksums
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(tx_mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(tx_mbuf, struct udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    // Generate header fields
    #ifdef HW_NO_CKSUM_OFFLOAD
    // case for offload unavailable
    udp_hdr->chksum = rte_ipv4_udptcp_cksum(ip_hdr, udp_hdr);
    ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
    #else
    // case for offload available
    udp_hdr->chksum = rte_ipv4_phdr_cksum(ip_hdr, offloads);
    ip_hdr->hdr_checksum = 0;
    #endif

    rte_memcpy(rte_pktmbuf_mtod(tx_mbuf, void *), bufptr, p->tot_len);
    rte_pktmbuf_pkt_len(tx_mbuf) = rte_pktmbuf_data_len(tx_mbuf) = p->tot_len;
    
    uint16_t ret = rte_eth_tx_burst(0, 0, &tx_mbuf, 1);

    if (largebuf)
        free(largebuf);
    rte_pktmbuf_free(tx_mbuf);
    return ERR_OK;
}

// LWIP interface init
static err_t if_init(struct netif *netif)
{
    // Set network MTU
    uint16_t mtu;
    assert(rte_eth_dev_get_mtu(0 /* port id */, &mtu) >= 0);
    assert(mtu <= PACKET_BUF_SIZE);
    netif->mtu = mtu;
    printf("\n\n Network MTU = %u\n\n", mtu);
    for (int i = 0; i < 6; i++)
        netif->hwaddr[i] = _mac[i];

    // Set up everything else.
    netif->output = etharp_output;
    netif->linkoutput = tx_output;
    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_ETHERNET;
    return ERR_OK;
}

// DPDK port init
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
#ifdef DEBUG
    printf("Setting up port %u\n", port);
#endif
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RING_SIZE;
    uint16_t nb_txd = RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    // Enable all multicast so UDP/DHCP/AP work
    rte_eth_allmulticast_enable(port);

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    // Get port info
    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0)
    {
        printf("Error during getting device (port %u) info: %s\n",
               port, strerror(-retval));
        return retval;
    }
    
    // Set offload optimisations if available
    port_conf.txmode.offloads = 
    RTE_ETH_TX_OFFLOAD_UDP_CKSUM | 
    RTE_ETH_TX_OFFLOAD_TCP_CKSUM | 
    RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
    
    port_conf.rxmode.offloads =
    RTE_ETH_RX_OFFLOAD_CHECKSUM;


    // // Fast free
    // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    // 	port_conf.txmode.offloads |=
    // 		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    // // ipv4 checksums
    // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
    //     port_conf.txmode.offloads |=
    //         RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;

    // // udp checksums
    // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
    //     port_conf.txmode.offloads |=
    //         RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    // Set up ethernet. We don't actually have anything in the struct
    // except for the offload optimisation.
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Check that queue descriptors are appropriately sized
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    // Set up RX queue for each rx ring
    // This isn't needed for all portssince we have on port
    // dedicated to RX, other to TX
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                                        rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    // Same thing as above, but for TX
    txconf = dev_info.default_txconf; // Unclear why we need this for tx but not rx
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    // Kick device to start
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    // Grab and print MAC
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0)
        return retval;
    for (int i = 0; i < 6; i++)
        _mac[i] = addr.addr_bytes[i];

    rte_eth_promiscuous_enable(port);

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
           port, RTE_ETHER_ADDR_BYTES(&addr));
    return 0;
}

static void udp_recv_handler(void *arg __attribute__((unused)),
                             struct udp_pcb *upcb,
                             struct pbuf *p, const ip_addr_t *addr,
                             u16_t port)
{
#ifdef DEBUG
    printf("UDP echoing packet with length %d totallen %d\n", p->len, p->tot_len);
#endif
    err_t ret = udp_sendto(upcb, p, addr, port) == ERR_OK;
    if (ret < 0)
    {
        printf("WARNING: failed to transmit back to client\n");
    }

// Print packet
#ifdef DEBUG
    uint8_t *data = p->payload;
    printf("Packet data: ");
    for (uint16_t i = 0; i < p->len; ++i)
    {
        printf("%c", data[i]);
    }
    printf("\n");

    printf("Echoing packet to %s:%d\n", ipaddr_ntoa(addr), port);
#endif
}
struct netif netif = {0};
static struct udp_pcb *upcb;
// Main loop
static __rte_noreturn void lcore_main(void)
{
    // LWIP setup
    ip4_addr_t _addr, _mask, _gate;

    inet_pton(AF_INET, "255.255.255.0", &_mask);
    inet_pton(AF_INET, "0.0.0.0", &_gate);
    inet_pton(AF_INET, "0.0.0.0", &_addr);

    lwip_init();
    LWIP_MEMPOOL_INIT(RX_POOL);
    assert(netif_add(&netif, &_addr, &_mask, &_gate, NULL, if_init, ethernet_input) != NULL);
    netif_set_default(&netif);
    netif_set_link_up(&netif);

    // Create a new thread to run the lwip timer
    pthread_t thread;
    pthread_attr_t attr;
    size_t stacksize = DEFAULT_THREAD_STACKSIZE;

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stacksize);

    pthread_create(&thread, &attr, lwip_timeouts_thread, NULL);
    pthread_attr_destroy(&attr);

    // Adjust thread priority if needed
    struct sched_param param;
    param.sched_priority = DEFAULT_THREAD_PRIO;

    pthread_setschedparam(thread, SCHED_OTHER, &param);
    struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];

    dhcp_setup(&netif);
    // While waiting for DHCP, perform minimal receipt loop
    printf("Awaiting DHCP...\n");
    while (dhcp_addr_supplied(&netif) == 0)
    {
        unsigned short i, nb_rx = rte_eth_rx_burst(0 /* port id */, 0 /* queue id */, rx_mbufs, MAX_PKT_BURST);
        for (i = 0; i < nb_rx; i++)
        {
            struct pbuf *p;
            
            assert((p = alloc_custom_pbuf(rx_mbufs[i])) != NULL);
            assert(netif.input(p, &netif) == ERR_OK);
            // rte_pktmbuf_free(rx_mbufs[i]);
        }
    }
    printf("\n\n\n\n #### DHCP REGISTERED #### \n\n\n\n");
    
    // Set up UDP
    udp_init();
    assert((upcb = udp_new()) != NULL);
    udp_bind(upcb, IP_ANY_TYPE, 1234);
    udp_recv(upcb, udp_recv_handler, upcb);

    // Send a packet to the gateway to force LWIP to add it to the etharp cache.
    udp_sendto(upcb, pbuf_alloc(PBUF_RAW, 0, PBUF_POOL), &netif.gw, 1234);
    

    /* primary loop */
    while (1)
    {
        unsigned short i, nb_rx = rte_eth_rx_burst(0 /* port id */, 0 /* queue id */, rx_mbufs, MAX_PKT_BURST);
        for (i = 0; i < nb_rx; i++)
        {
            struct pbuf *p;
            assert((p = alloc_custom_pbuf(rx_mbufs[i])) != NULL);

// Print packet contents
#ifdef DEBUG
            uint8_t *data = rte_pktmbuf_mtod(rx_mbufs[i], uint8_t *);
            uint32_t len = rte_pktmbuf_pkt_len(rx_mbufs[i]);
            for (uint32_t j = 0; j < len; j++)
            {
                printf("%02X ", data[j]);
                if ((j + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");
#endif
            assert(netif.input(p, &netif) == ERR_OK);
            // rte_pktmbuf_free(rx_mbufs[i]);
        }
    }
}

int main(int argc, char *argv[])
{
    // # DPDK init #
    unsigned nb_ports;
    uint16_t portid;
    int ret;

    // Start EAL
    if ((ret = rte_eal_init(argc, argv)) < 0)
    {
        rte_exit(EXIT_FAILURE, "EAL failed to initialise\n");
    }

    // Find ports
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports != 2)
        rte_exit(EXIT_FAILURE, "Error: Must have exactly 2 ports available! Actual: %u\n", nb_ports);

    // Allocate rx mempool
    assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
                                                   RTE_MAX(1 /* nb_ports */ * (RING_SIZE * 2 + MAX_PKT_BURST + 1 * MEMPOOL_CACHE_SIZE), 8192),
                                                   MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id())) != NULL);
    if (pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "mbuf pool could not be created!\n");

    // Set up ports
    RTE_ETH_FOREACH_DEV(portid)
    {
        if (port_init(portid, pktmbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
                     portid);
        break; // only do one port for now
    }

    

    // Sanity checks
    if (rte_lcore_count() > 1)
        printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");


    // Start main loop
    lcore_main();

    // Cleanup and die
    rte_eal_cleanup();
    return 0;
}