/*
 *
 * Copyright 2022 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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

#define MAX_PKT_BURST (32)
#define NUM_SLOT (256)

#define MEMPOOL_CACHE_SIZE (256)

#define PACKET_BUF_SIZE (1518)

static struct rte_mempool *pktmbuf_pool = NULL;
static int tx_idx = 0;
static struct rte_mbuf *tx_mbufs[MAX_PKT_BURST] = {0};

#define LINK_SPEED 1000000000 // Gigabit
#define ETHER_MTU 1500
#define NUM_BUFFERS 512
#define BUF_SIZE 2048
#define PORT_NUM 0


static void tx_flush(void)
{
	int xmit = tx_idx, xmitted = 0;
	while (xmitted != xmit) {
		xmitted += rte_eth_tx_burst(PORT_NUM /* port id */, 0 /* queue id */, &tx_mbufs[xmitted], xmit - xmitted);
		printf("xmit loop: %d\n", xmitted);
	}
	tx_idx = 0;
	if (xmitted)
		printf("xmitted %d packets\n", xmitted);
}

static err_t low_level_output(struct netif *netif __attribute__((unused)), struct pbuf *p)
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
	else
		bufptr = buf;

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

static unsigned long io_stat[3] = {0};

static err_t if_init(struct netif *netif)
{
	{
		struct rte_ether_addr ports_eth_addr;
		assert(rte_eth_macaddr_get(PORT_NUM /* port id */, &ports_eth_addr) >= 0);
		printf("Hardware address: ");
		for (int i = 0; i < 6; i++) {
			netif->hwaddr[i] = ports_eth_addr.addr_bytes[i];
			printf("%x", netif->hwaddr[i]);
		}
		printf("\n");
	}
	{
		uint16_t _mtu;
		assert(rte_eth_dev_get_mtu(PORT_NUM /* port id */, &_mtu) >= 0);
		assert(_mtu <= PACKET_BUF_SIZE);
		netif->mtu = _mtu;
	}
	netif->output = etharp_output;
	netif->linkoutput = low_level_output;
	netif->hwaddr_len = 6;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP | NETIF_FLAG_LINK_UP;
	return ERR_OK;
}



int main(int argc, char *const *argv)
{
	printf("### STARTING ###\n");
	struct netif _netif = {0};
	ip4_addr_t _addr, _mask, _gate, _srv_ip;

	/* setting up dpdk */
	{
		int ret;
		uint16_t nb_rxd = NUM_SLOT;
		uint16_t nb_txd = NUM_SLOT;
		printf("Initialising EAL\n");
		assert((ret = rte_eal_init(argc, (char **)argv)) >= 0);
		printf("EAL initialised!\n");
		argc -= ret;
		argv += ret;
		assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
													   RTE_MAX(1 /* nb_ports */ * (nb_rxd + nb_txd + MAX_PKT_BURST + 1 * MEMPOOL_CACHE_SIZE), 8192),
													   MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
													   rte_socket_id())) != NULL);

		{
			struct rte_eth_dev_info dev_info;
			struct rte_eth_conf local_port_conf = {0};

			assert(rte_eth_dev_info_get(PORT_NUM /* port id */, &dev_info) >= 0);

			assert(rte_eth_dev_configure(PORT_NUM /* port id */, 1 /* num queues */, 1 /* num queues */, &local_port_conf) >= 0);

			assert(rte_eth_dev_adjust_nb_rx_tx_desc(0 /* port id */, &nb_rxd, &nb_txd) >= 0);

			assert(rte_eth_rx_queue_setup(PORT_NUM /* port id */, 0 /* queue */, nb_rxd,
										  rte_eth_dev_socket_id(0 /* port id */),
										  &dev_info.default_rxconf,
										  pktmbuf_pool) >= 0);

			assert(rte_eth_tx_queue_setup(PORT_NUM /* port id */, 0 /* queue */, nb_txd,
										  rte_eth_dev_socket_id(0 /* port id */),
										  &dev_info.default_txconf) >= 0);

			assert(rte_eth_dev_start(PORT_NUM /* port id */) >= 0);
			assert(rte_eth_promiscuous_enable(PORT_NUM /* port id */) >= 0);
		}
	}
	printf("DPDK initialised!\n");

	/* setting up lwip */
	{
		printf("Initializing lwip...\n");
		lwip_init();
		inet_pton(AF_INET, "0.0.0.0", &_mask);
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
	}

	// Start echo thread
	// sys_thread_new("udpecho_thread", udpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);

	printf("-- application has started --\n");

	/* primary loop */
	{
		unsigned long prev_ts = 0;
		while (1)
		{
			struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
			unsigned short i, nb_rx = rte_eth_rx_burst(PORT_NUM /* port id */, 0 /* queue id */, rx_mbufs, MAX_PKT_BURST);
			for (i = 0; i < nb_rx; i++)
			{
				{
					printf("packet received\n");
					struct pbuf *p;
					assert((p = pbuf_alloc(PBUF_RAW, rte_pktmbuf_pkt_len(rx_mbufs[i]), PBUF_POOL)) != NULL);
					pbuf_take(p, rte_pktmbuf_mtod(rx_mbufs[i], void *), rte_pktmbuf_pkt_len(rx_mbufs[i]));
					p->len = p->tot_len = rte_pktmbuf_pkt_len(rx_mbufs[i]);
					assert(_netif.input(p, &_netif) == ERR_OK);
					
					// Print packet
					char buf[PACKET_BUF_SIZE];
					void *bufptr, *largebuf = NULL;
					if (sizeof(buf) < p->tot_len)
					{
						largebuf = (char *)malloc(p->tot_len);
						assert(largebuf);
						bufptr = largebuf;
					}
					else
						bufptr = buf;

					pbuf_copy_partial(p, bufptr, p->tot_len, 0);
					
					for (int i = 0; i < p->tot_len; i++)
					{
						printf("%02x ", ((unsigned char *)bufptr)[i]);
						if (i % 16 == 15)
							printf("\n");
					}
					printf("\n");
				}
				rte_pktmbuf_free(rx_mbufs[i]);
			}
			tx_flush();
			sys_check_timeouts();
			{
				unsigned long now = ({ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); (ts.tv_sec * 1000000000UL + ts.tv_nsec); });
				if (now - prev_ts > 1000000000UL)
				{
					memset(io_stat, 0, sizeof(io_stat));
					prev_ts = now;
				}
			}
		}
	}

	return 0;
}
