// main.c
// Main part of lwip-dpdk udp echo
// Matt Rossouw (omeh-a)
// 31/05/2023

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

#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/sys.h"

#include <netif/ethernet.h>

#include <netif/ethernet.h>
#include "udpecho.h"

#define PORT_RX 0
#define PORT_TX 0

// DPDK constants
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

// LWIP constants
#define LINK_SPEED 1000000000 // Gigabit
#define ETHER_MTU 1500
#define NUM_BUFFERS 512
#define BUF_SIZE 2048
#define MAX_PKT_BURST (32)
#define NUM_SLOT (256)
#define MEMPOOL_CACHE_SIZE (256)
#define PACKET_BUF_SIZE (1518)

// LWIP/DPDK interfacing globals
static struct rte_mempool *pktmbuf_pool = NULL;
static int tx_idx = 0;
static struct rte_mbuf *tx_mbufs[MAX_PKT_BURST] = {0};
static uint8_t mac[6] = {0xb4, 0x96, 0x91, 0x6a, 0x7f, 0x2c};

static void tx_flush(void)
{
	int xmit = tx_idx, xmitted = 0;
	while (xmitted != xmit) {
		xmitted += rte_eth_tx_burst(PORT_TX /* port id */, 0 /* queue id */, &tx_mbufs[xmitted], xmit - xmitted);
		printf("xmit loop: outputting a burst %d -> burst size = %d\n", xmitted, xmit- xmitted);
	}
	tx_idx = 0;
	if (xmitted)
		printf("xmitted %d packets\n", xmitted);
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
    
	assert((tx_mbufs[tx_idx] = rte_pktmbuf_alloc(pktmbuf_pool)) != NULL);
	assert(p->tot_len <= RTE_MBUF_DEFAULT_BUF_SIZE);
	rte_memcpy(rte_pktmbuf_mtod(tx_mbufs[tx_idx], void *), bufptr, p->tot_len);
	rte_pktmbuf_pkt_len(tx_mbufs[tx_idx]) = rte_pktmbuf_data_len(tx_mbufs[tx_idx]) = p->tot_len;
	if (++tx_idx == MAX_PKT_BURST)
		tx_flush();

	if (largebuf)
		free(largebuf);
	return ERR_OK;
}

// LWIP interface init
static err_t if_init(struct netif *netif) {
    struct rte_ether_addr ports_eth_addr;
    
    // Set network MTU for rx and hope it works for tx. It should.
    uint16_t _mtu_rx;
    assert(rte_eth_dev_get_mtu(PORT_RX /* port id */, &_mtu_rx) >= 0);
    assert(_mtu_rx <= PACKET_BUF_SIZE);
    netif->mtu = _mtu_rx;
    for (int i = 0; i < 6; i++)
        netif->hwaddr[i] = mac[i];

    // Set up everything else.
    netif->output = etharp_output;
	netif->linkoutput = tx_output;
	netif->hwaddr_len = 6;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP;
	return ERR_OK;
}

// DPDK port init
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    printf("Setting up port %u\n", port);
    struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;
    
	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    // Get port info
    retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}
    // Set offload optimisations if available
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    
    // Set up ethernet. We don't actually have anything in the struct
    // except for the offload optimisation.
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    // Check that queue descriptors are appropriately sized
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0) return retval;

    // Set up RX queue for each rx ring
    // This isn't needed for all portssince we have on port 
    // dedicated to RX, other to TX
    /* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

    // Same thing as above, but for TX
    txconf = dev_info.default_txconf;   // Unclear why we need this for tx but not rx
	txconf.offloads = port_conf.txmode.offloads;
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

    // Kick device to start
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    // Grab and print MAC
    struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));
    return 0;
}

// Main loop
static __rte_noreturn void lcore_main(struct netif netif)
{
    uint16_t port;
    for (;;) {

		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
            
            // Inject packets to LWIP
            for (int i = 0; i < nb_rx; i++) {
                // Create LWIP packet buffer from rte_mbuf
                // This is horribly inefficient and once this works this should change to
                // either:
                // A: Create an array of packet buffers which are recycled to avoid allocations
                // B: Find a way to use the rte_mbuf directly
                printf("Packet arrived! #%d of burst sized %d\n", i, nb_rx);
                struct pbuf *p;

                // Allocate pbuf
                assert((p = pbuf_alloc(PBUF_RAW, rte_pktmbuf_pkt_len(bufs[i]), PBUF_POOL)) != NULL);
                
                // Copy data to pbuf from the DPDK mbuf
                pbuf_take(p, rte_pktmbuf_mtod(bufs[i], void *), rte_pktmbuf_pkt_len(bufs[i]));
                p->len = p->tot_len = rte_pktmbuf_pkt_len(bufs[i]);
                
                // Insert packet for real
                assert(netif.input(p, &netif) == ERR_OK);

                // // Print packet
                // char buf[PACKET_BUF_SIZE];
                // void *bufptr, *largebuf = NULL;
                // if (sizeof(buf) < p->tot_len)
                // {
                //     largebuf = (char *)malloc(p->tot_len);
                //     assert(largebuf);
                //     bufptr = largebuf;
                // }
                // else
                //     bufptr = buf;

                // pbuf_copy_partial(p, bufptr, p->tot_len, 0);
                
                // for (int i = 0; i < p->tot_len; i++)
                // {
                //     printf("%02x ", ((unsigned char *)bufptr)[i]);
                //     if (i % 16 == 15)
                //         printf("\n");
                // }
                // printf("\n");

                // Clean up
                rte_pktmbuf_free(bufs[i]);
                // if (largebuf) free(largebuf);
            }
            // Dispatch waiting packets
            tx_flush();

            // Check timeouts for DHCP, etc. using LWIP. Renews anything that needs it.
			sys_check_timeouts();

			// if (unlikely(nb_rx == 0))
			// 	continue;

			// /* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
			// 	uint16_t buf;
			// 	for (buf = nb_tx; buf < nb_rx; buf++)
			// 		rte_pktmbuf_free(bufs[buf]);
			// }
		}
	}
}


int main(int argc, char *argv[]) {
    printf("Initialising\n");

    struct netif _netif = {0};
	ip4_addr_t _addr, _mask, _gate, _srv_ip;

    // # DPDK init #
    struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
    int ret;

    // Start EAL
    if (ret = rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "EAL failed to initialise\n");
    }

    // Find ports
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports != 2)
		rte_exit(EXIT_FAILURE, "Error: Must have exactly 2 ports available! Actual: %u\n", nb_ports);
    
    // Allocate rx mempool
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "mbuf pool could not be created!\n");
    
    // Allocate tx mempool
    pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS * nb_ports,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    // Set up ports
    RTE_ETH_FOREACH_DEV(portid)
        {
            if (port_init(portid, mbuf_pool) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
                        portid);    
        }
    
    // Sanity checks
    if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    
    // # LWIP init #
    printf("Initializing lwip...\n");
    lwip_init();
    inet_pton(AF_INET, "255.255.255.0", &_mask);
    inet_pton(AF_INET, "0.0.0.0", &_gate);
    inet_pton(AF_INET, "0.0.0.0", &_addr);


    assert(netif_add(&_netif, &_addr, &_mask, &_gate, NULL, if_init, ethernet_input) != NULL);
    
    // DHCP
    netif_set_default(&_netif);
    err_t err = dhcp_setup(_netif);
    if (err) {
        printf("Failed to register with DHCP! err=%d\n", (int)err);
        return -1;
    }
    netif_set_link_up(&_netif);

    // Enter main loop
    lcore_main(_netif);

    // Cleanup and die
    rte_eal_cleanup();
    return 0;
}