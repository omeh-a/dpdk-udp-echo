# udp-dpdk-echo

UDP packet echo server implemented over DPDK. This runs on a single thread using a single port and is readily able to saturate a 10 gigabit connection, tested on a Core i9-12900KF with an Intel X570 network interface. This should work fine on other DPDK-compatible NICs.

**IMPORTANT**: You need to comment out line 1009 in `lwip/lwip-2.1.2/src/core/ipv4/etharp.c` for this to work. There is an assert which does little but is triggered whenever UDP load > one gibibit occurs. If there are complications to commenting this out, I am not aware of them.
```
// Comment this out
LWIP_ASSERT("no packet queues allowed!", (p->len != p->tot_len) || (p->next == 0));
```

This is needed because LWIP constructs linked lists of packets to send to the network interface; but when the etharp component needs to wait to refresh the DHCP lease / perform an arp request, it inexplicably won't allow the linked list to be longer than one entry. This assert seems to be the only actual issue however - things appear to work normally at least for UDP.

## Usage

Place the file on the target machine (can use `./install.sh` script to do this) and run using the command

```
sudo LD_LIBRARY_PATH=./dpdk/dpdk-stable-22.11.1/install/lib/x86_64-linux-gnu ./udpecho-l 0-1 --proc-type=primary --file-prefix=pmd1
```

... making sure to include the appropriate directory for a DPDK installation matching the one used to build the program. **You need to set up DPDK and attach the `vfio-pci` driver to your target network device!**. Follow the DPDK Linux Quick-start guide for help on this.

If you want to run this on your local machine, ignore the moving instructions and just run the command :)

