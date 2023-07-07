#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include "utilisation.h"

#define BUFFER_SIZE 5000
#define MAX_BACKLOG 50

/* This file implements a TCP based utilization measurment process that starts
 * and stops utilization measurements based on a client's requests.
 * The protocol used to communicate is as follows:
 * - Client connects
 * - Server sends: 100 IPBENCH V1.0\n
 * - Client sends: HELLO\n
 * - Server sends: 200 OK (Ready to go)\n
 * - Client sends: LOAD cpu_target_lukem\n
 * - Server sends: 200 OK\n
 * - Client sends: SETUP args::""\n
 * - Server sends: 200 OK\n
 * - Client sends: START\n
 * - Client sends: STOP\n
 * - Server sends: 220 VALID DATA (Data to follow)\n
 *                                Content-length: %d\n
 *                                ${content}\n
 * - Server closes socket.
 *
 * It is also possible for client to send QUIT\n during operation.
 *
 * The server starts recording utilization stats when it receives START and
 * finishes recording when it receives STOP.
 *
 * Only one client can be connected.
 */
#define WHOAMI "100 IPBENCH V1.0\n"
#define HELLO "HELLO\n"
#define OK_READY "200 OK (Ready to go)\n"
#define LOAD "LOAD cpu_target_lukem\n"
#define OK "200 OK\n"
#define SETUP "SETUP args::\"\"\n"
#define START "START\n"
#define STOP "STOP\n"
#define QUIT "QUIT\n"
#define RESPONSE "220 VALID DATA (Data to follow)\n"    \
    "Content-length: %d\n"                              \
    "%s\n"
#define IDLE_FORMAT ",%ld,%ld"
#define ERROR "400 ERROR\n"

#define msg_match(msg, match) (strncmp(msg, match, strlen(match))==0)

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define RES(x, y, z) "220 VALID DATA (Data to follow)\n"    \
    "Content-length: "STR(x)"\n"\
    ","STR(y)","STR(z)

#define PORT 1236

char buf[BUFFER_SIZE];

#define NUM_CORES 4
/* idle threads */
static pthread_t ithr0;
static pthread_t ithr1;
static pthread_t ithr2;
static pthread_t ithr3;

/* stores timer information */
struct timer_info {
    volatile struct timer_buffer_t timer_buffer[NUM_CORES];
};

/* Records start times for idle threads */
uint64_t start[NUM_CORES];
uint64_t idle_ccount_start[NUM_CORES];
struct timer_info timer_info;

static int
process_msg(int client, const void *buf, size_t num_bytes)
{
    int error;
    char buffer[100];
    if (msg_match(buf, HELLO)) {
	snprintf(buffer, strlen(OK_READY) + 1, OK_READY);
        error = send(client, buffer, strlen(OK_READY), 0x0);
        if (error < 0) {
            printf("Failed to send OK_READY message through utilization peer");
        }
    } else if (msg_match(buf, LOAD)) {
	snprintf(buffer, strlen(OK) + 1, OK);
        error = send(client, buffer, strlen(OK), 0x0);
        if (error < 0) {
            printf("Failed to send OK message through utilization peer");
        }
    } else if (msg_match(buf, SETUP)) {
	snprintf(buffer, strlen(OK) + 1, OK);
        error = send(client, buffer, strlen(OK), 0x0);
        if (error < 0) {
            printf("Failed to send OK message through utilization peer");
        }
    } else if (msg_match(buf, START)) {
        printf("measurement starting... \n");
	for (int i = 0; i < NUM_CORES; i++) {
            start[i] = timer_info.timer_buffer[i].total;
            idle_ccount_start[i] = timer_info.timer_buffer[i].idle;
        }
    } else if (msg_match(buf, STOP)) {
        printf("measurement finished \n");
	
	    char core0[16];
	    char core1[16];
	    char core2[16];
	    char core3[16];
        sprintf(core0, "%.1f", (1.f - ((double)timer_info.timer_buffer[0].idle/(double)timer_info.timer_buffer[0].total)) * 100);
        sprintf(core1, "%.1f", (1.f - ((double)timer_info.timer_buffer[1].idle/(double)timer_info.timer_buffer[1].total)) * 100);
        sprintf(core2, "%.1f", (1.f - ((double)timer_info.timer_buffer[2].idle/(double)timer_info.timer_buffer[2].total)) * 100);
        sprintf(core3, "%.1f", (1.f - ((double)timer_info.timer_buffer[3].idle/(double)timer_info.timer_buffer[3].total)) * 100);
        
        int len = strlen(core0) + strlen(core1) + strlen(core2) + strlen(core3) + 4;

        snprintf(buffer, 100, "220 VALID DATA (Data to follow)\nContent-length: %d\n%s,%s,%s,%s\n", len, core0, core1, core2, core3);
        error = send(client, buffer, strlen(buffer), 0x0);
        if (error < 0) {
            printf("Failed to send final message through utilisation peer\n");
        }
        return -1;
    } else if (msg_match(buf, QUIT)) {
        return -1;
    } else {
        printf("Received a message we can't handle: %s\n", buf);

    }

    return 0;
}

void *idle_thread(void *arg)
{
    int core_num = *((int *) arg);
    printf("Starting idle thread on core %d\n", core_num);
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(core_num, &my_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &my_set);

    uint64_t x0, x1, delta, total, idle;

    idle = total = 0;
    x0 = aarch64_get_cycles();

    while (1) {
        x1 = x0;
        x0 = aarch64_get_cycles();
            
        delta = x0 - x1;
        total += delta;
            
        /* If the delta looks like less than a context switch,
            * add this to idle time; otherwise add it to busy
            * time */
        if (delta < PROFILE_CONTEXT_COST)
            idle += delta;
                
        timer_info.timer_buffer[core_num].idle = idle;
        timer_info.timer_buffer[core_num].total = total;
    }

    return 0;
}


int main(int argc, const char *argv[])
{
    /* create the idle threads */
    int arg0 = 0;
    int arg1 = 1;
    int arg2 = 2;
    int arg3 = 3;
    pthread_create(&ithr0, NULL, &idle_thread, &arg0);
    pthread_create(&ithr1, NULL, &idle_thread, &arg1);
    pthread_create(&ithr2, NULL, &idle_thread, &arg2);
    pthread_create(&ithr3, NULL, &idle_thread, &arg3);

    struct sockaddr_in sockAddr;
    struct sockaddr_in clientAddr;
    socklen_t sockAddrLen;
    ssize_t msgLen;

    // Prepare socket address
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_port = htons(1236);
    sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (!sock) {
        printf("Failed to create socket!");
        return -1;
    }

    // Set buffer
    /*int bufsize = BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof bufsize);
    */	
    // Try bind
    if (bind(sock, (struct sockaddr *)&sockAddr, sizeof sockAddr)) {
        printf("Failed to bind.");
        return -1;
    }

    // Begin listen
    if(listen(sock, MAX_BACKLOG)) {
        printf("Failed to begin listening.");
        return -1;
    }

    // Server loop
    for (;;) {
        sockAddrLen = sizeof sockAddr;
        size_t num_bytes = 0; // Size of received message

        // Accept next client
        int client = accept(sock, (struct sockaddr *)&sockAddr, &sockAddrLen);
        printf("Utilisation connection established\n");
	// send who am i message. 
	char msg[50];
	snprintf(msg, strlen(WHOAMI) + 1, WHOAMI);
	if (send(client, msg, strlen(WHOAMI), 0x0) < 0) {
	    printf("Failed to send WHOAMI message\n");
	    break;
	}	

        // Receive until client releases
        while ((num_bytes = recv(client, buf, BUFFER_SIZE, 0x0))) {
	    if (process_msg(client, buf, num_bytes)) {
                break;
            }
        }

        // Terminate connection
        close(client);
    }
}
