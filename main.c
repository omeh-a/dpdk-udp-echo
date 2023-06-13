// please work this time
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include <arpa/inet.h>

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

/* workaround to avoid conflicts between dpdk and lwip definitions */
#undef IP_DF
#undef IP_MF
#undef IP_RF
#undef IP_OFFMASK

#include <lwip/opt.h>
#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <lwip/udp.h>
#include <lwip/timeouts.h>
#include <netif/ethernet.h>

#include "udpecho.h"
#include "lwipopts.h"

#define MAX_PKT_BURST (128)
#define RING_SIZE (1024)

#define MEMPOOL_CACHE_SIZE (256)

#define PACKET_BUF_SIZE (1518)
#define NUM_MBUFS (8192)

static struct rte_mempool *pktmbuf_pool = NULL;
static int mbuf_count = 0;
static struct rte_mbuf *tx_mbufs[MAX_PKT_BURST] = {0};

#define MAX_QUEUE_DEPTH (4096)
static bool is_client = false;
static unsigned long counter[MAX_QUEUE_DEPTH] = {0};
static int init_state = 0;
static uint8_t _mac[6];
static uint16_t _mtu;

static void tx_flush(void)
{
    int emission_index = mbuf_count;
    int emitted = 0;
    while (emitted != emission_index)
        emitted += rte_eth_tx_burst(0 /* port id */, 0 /* queue id */, &tx_mbufs[emitted], emission_index - emitted);
    printf("TX_FLUSH PACKET:\n");
    
        // Print the packet content if it is transmitted
        if (emitted) {
            for (int i = 0; i < rte_pktmbuf_data_len(tx_mbufs[emitted-1]); i++) {
                printf("%02x ", ((unsigned char *)rte_pktmbuf_mtod(tx_mbufs[emitted-1], unsigned char*))[i]);
                if (i % 16 == 15)
                    printf("\n");
            }
            printf("\n");
        }

    mbuf_count = 0;

    // print packet
    printf("Emitted %d packets\n", emitted);
}

// Function to output packets for lwip
static err_t tx_output(struct netif *netif __attribute__((unused)), struct pbuf *p)
{
    printf("Attempting to output packet ...\n");
	char buf[PACKET_BUF_SIZE];
	void *bufptr, *largebuf = NULL;
	if (sizeof(buf) < p->tot_len)
	{
		largebuf = (char *)malloc(p->tot_len);
		assert(largebuf);
		bufptr = largebuf;
	}
	else {
		bufptr = buf;
        largebuf = NULL;
    }

	pbuf_copy_partial(p, bufptr, p->tot_len, 0);
	printf("Packet size: %d\n", p->tot_len);

	// Print packet
	for (int i = 0; i < p->tot_len; i++)
	{
		printf("%02x ", ((unsigned char *)bufptr)[i]);
		if (i % 16 == 15)
			printf("\n");
	}
    
	assert((tx_mbufs[mbuf_count] = rte_pktmbuf_alloc(pktmbuf_pool)) != NULL);
	assert(p->tot_len <= RTE_MBUF_DEFAULT_BUF_SIZE);
    printf("Storing packet in tx_mbufs[%d]\n", mbuf_count);
	rte_memcpy(rte_pktmbuf_mtod(tx_mbufs[mbuf_count], void *), bufptr, p->tot_len);
	rte_pktmbuf_pkt_len(tx_mbufs[mbuf_count]) = rte_pktmbuf_data_len(tx_mbufs[mbuf_count]) = p->tot_len;
	if (++mbuf_count == MAX_PKT_BURST)
    
	if (largebuf)
		free(largebuf);
    tx_flush();
	return ERR_OK;
}

// LWIP interface init
static err_t if_init(struct netif *netif)
{
    struct rte_ether_addr ports_eth_addr;

    

    // Set network MTU
    uint16_t mtu;
    assert(rte_eth_dev_get_mtu(0 /* port id */, &mtu) >= 0);
    assert(mtu <= PACKET_BUF_SIZE);
    netif->mtu = mtu;
    for (int i = 0; i < 6; i++)
        netif->hwaddr[i] = _mac[i];

    // Set up everything else.
    netif->output = etharp_output;
    netif->linkoutput = tx_output;
    netif->hwaddr_len = 6;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | 
                   NETIF_FLAG_LINK_UP | NETIF_FLAG_ETHERNET;
    return ERR_OK;
}

// DPDK port init
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    printf("Setting up port %u\n", port);
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
    // if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
    // 	port_conf.txmode.offloads |=
    // 		RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

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
    
    // rte_eth_promiscuous_enable(port); 

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

    printf("UDP packet received!\n");
    // if (p == NULL) return;
    assert(udp_sendto(upcb, p, addr, port) == ERR_OK);

    // Print packet 
    uint8_t *data = p->payload;
    printf("Packet data: ");
    for (uint16_t i = 0; i < p->len; ++i) {
        printf("%c", data[i]);
    }
    printf("\n");
    
    printf("Echoing packet to %s:%d\n", ipaddr_ntoa(addr), port);
    pbuf_free(p);
    tx_flush();
}

static struct udp_pcb *upcb;
// Main loop
static __rte_noreturn void lcore_main(struct netif netif)
{
    printf("Main loop starting\n");
    uint16_t port;
    int queue_depth = 1;
    size_t additional_payload_len = 0;
    struct timespec _t;
    
    sys_check_timeouts();
    // Create UDP process control block and bind to port 1234
    ip4_addr_t _addr = IPADDR4_INIT_BYTES(172, 16, 0, 69);
    ip4_addr_t _gateway = IPADDR4_INIT_BYTES(172, 16, 0, 1);
    
    udp_init();
    
    assert((upcb = udp_new_ip_type(IPADDR_TYPE_V4)) != NULL);
    udp_bind(upcb, IP_ADDR_ANY, 1234);
    udp_recv(upcb, udp_recv_handler, upcb);
    tx_flush();
    /* primary loop */
    while (1)
    {
        struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
        unsigned short i, nb_rx = rte_eth_rx_burst(0 /* port id */, 0 /* queue id */, rx_mbufs, MAX_PKT_BURST);
        for (i = 0; i < nb_rx; i++)
        {
            printf("Packet received! \n");
            
            struct pbuf *p;
            assert((p = pbuf_alloc(PBUF_RAW, rte_pktmbuf_pkt_len(rx_mbufs[i]), PBUF_POOL)) != NULL);
            pbuf_take(p, rte_pktmbuf_mtod(rx_mbufs[i], void *), rte_pktmbuf_pkt_len(rx_mbufs[i]));
            p->len = p->tot_len = rte_pktmbuf_pkt_len(rx_mbufs[i]);

            // Print packet contents
            uint8_t *data = rte_pktmbuf_mtod(rx_mbufs[i], uint8_t *);
            uint32_t len = rte_pktmbuf_pkt_len(rx_mbufs[i]);
            for (uint32_t j = 0; j < len; j++)
            {
                printf("%02X ", data[j]);
                if ((j + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");

            assert(netif.input(p, &netif) == ERR_OK);
            rte_pktmbuf_free(rx_mbufs[i]);
        }
        // sys_check_timeouts();
    }
}

int main(int argc, char *argv[])
{
    size_t additional_payload_len = 0;
    int queue_depth = 1;


    // DPDK init
    struct netif _netif = {0};
    ip4_addr_t _addr, _mask, _gate;

    inet_pton(AF_INET, "255.255.255.0", &_mask);
    inet_pton(AF_INET, "172.16.0.1", &_gate);
    inet_pton(AF_INET, "172.16.0.69", &_addr);



    // # DPDK init #
    unsigned nb_ports;
    uint16_t portid;
    int ret;

    // Start EAL
    if (ret = rte_eal_init(argc, argv) < 0)
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

    /* setting up lwip */
    lwip_init();
    assert(netif_add(&_netif, &_addr, &_mask, &_gate, NULL, if_init, ethernet_input) != NULL);
    netif_set_default(&_netif);

    netif_set_up(&_netif);
    netif_set_link_up(&_netif);
    dhcp_setup(_netif);
    // Start main loop
    lcore_main(_netif);


    // Cleanup and die
    rte_eal_cleanup();
    return 0;
}