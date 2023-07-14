/*
 * Copyright 2023, UNSW
 * SPDX-License-Identifier: BSD-2-Clause
 */

// Standard imports
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <pthread.h>
#include <arpa/inet.h>

// DPDK imports
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

// LWIP imports
#include "lwip/init.h"
#include "netif/etharp.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/stats.h"
#include "lwip/snmp.h"
#include "lwip/sys.h"
#include "lwip/dhcp.h"
#include <netif/ethernet.h>

// Undefining things that cause conflicts between LWIP and DPDK
#undef IP_DF
#undef IP_MF
#undef IP_RF
#undef IP_OFFMASK

// Other headers from repo
#include "udpecho.h"
#include "lwipopts.h"

// Constants
#define MAX_PKT_BURST (512)
#define RING_SIZE (1024)
#define MEMPOOL_CACHE_SIZE (256)
#define PACKET_BUF_SIZE (1518)
#define NUM_MBUFS (8192)

