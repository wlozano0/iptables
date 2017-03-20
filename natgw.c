/*
 * This code is GPL.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define BUFSIZE 2048

void showPacket (char *pktData, int pktLen) {
    int i = 0;
    printf ("\n Raw packet: --------------------------\n");
    for (i = 0; i < pktLen; i++) {
        printf ("%c", pktData[i]);
    }
    printf ("\n End of raw packet ------------------\n");
}

/* Checksum for IP header 
 */
unsigned short checksum (unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}


static int nfqCallback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData) {
    uint32_t id = 0;
    char *pktData;
    int pktLen;
    struct nfqnl_msg_packet_hdr *header;

    header = nfq_get_msg_packet_hdr(pkt);
    if (header) {
        id = ntohl(header->packet_id);
    }

    pktLen = nfq_get_payload(pkt, &pktData);

    //Cast to IP
    struct iphdr *iph = ((struct iphdr *) pktData);
    //Cast to UDP
    struct udphdr *udp =
        (struct udphdr *) (pktData + (iph->ihl << 2));
    //showPacket(m);

    //Change UDP Source Port
    udp->source = htons (ntohs (udp->source) + 2);

    //Recalculate checksum
    //iph->check=0;
    //iph->check=checksum((unsigned short*)iph,iph->ihl*4);

    udp->check = 0;

    //Accept packet

    return nfq_set_verdict(qh, id, NF_ACCEPT, pktLen, pktData);

}

int main (int argc, char **argv) {
    int status;
    struct nfq_handle *nfqHandle;
    struct nfq_q_handle *myQueue;
    struct nfnl_handle *netlinkHandle;
    int fd, res;
    unsigned char buf[BUFSIZE];
    struct ipq_handle *h;
    unsigned int iphl;

    // Get a queue connection handle from the module
    if (!(nfqHandle = nfq_open())) {
        fprintf (stderr,  "Error in nfq_open()\n");
        exit(-1);
    }

    // Unbind the handler from processing any IP packets
    // Not totally sure why this is done, or if it's necessary...
    if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
        fprintf (stderr, "Error in nfq_unbind_pf()\n");
        exit(1);
    }

    // Bind this handler to process IP packets...
    if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
        fprintf (stderr, "Error in nfq_bind_pf()\n");
        exit(1);
    }

    // Install a callback on queue 0
    if (!(myQueue = nfq_create_queue(nfqHandle,  0, &nfqCallback, NULL))) {
        fprintf (stderr, "Error in nfq_create_queue()\n");
        exit(1);
    }

    // Turn on packet copy mode
    if (nfq_set_mode(myQueue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf (stderr, "Could not set packet copy mode\n");
        exit(1);
    }

    netlinkHandle = nfq_nfnlh(nfqHandle);
    fd = nfnl_fd(netlinkHandle);

    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
        // I am not totally sure why a callback mechanism is used
        // rather than just handling it directly here, but that
        // seems to be the convention...
        nfq_handle_packet(nfqHandle, buf, res);
        // end while receiving traffic
    }

    nfq_destroy_queue(myQueue);

    nfq_close(nfqHandle);

    return 0;
}
