/*
 * This code is GPL.
 */
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libipq.h>

#define BUFSIZE 2048

void showPacket (ipq_packet_msg_t * pkt) {
    int i = 0;
    printf ("\n Raw packet: --------------------------\n");
    for (i = 0; i < pkt->data_len; i++) {
        printf ("%x", pkt->payload[i]);
    }
    printf ("\n End of raw packet ------------------");
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

static void die (struct ipq_handle *h) {
    ipq_perror ("passer");
    ipq_destroy_handle (h);
    exit (1);
}


int main (int argc, char **argv) {
    int status;
    unsigned char buf[BUFSIZE];
    struct ipq_handle *h;
    unsigned int iphl;

    h = ipq_create_handle (0, PF_INET);
    if (!h)
        die (h);

    status = ipq_set_mode (h, IPQ_COPY_PACKET, BUFSIZE);
    if (status < 0)
        die (h);

    do {
        status = ipq_read (h, buf, BUFSIZE, 0);
        if (status < 0)
            die (h);

        switch (ipq_message_type (buf)) {
        case NLMSG_ERROR:
            fprintf (stderr, "Received error message %d\n",
                     ipq_get_msgerr (buf));
            break;

        case IPQM_PACKET:{
                ipq_packet_msg_t *m = ipq_get_packet (buf);

                //Cast to IP
                struct iphdr *iph = ((struct iphdr *) m->payload);
                //Cast to UDP
                struct udphdr *udp =
                    (struct udphdr *) (m->payload + (iph->ihl << 2));


                //fprintf(stderr, "Packet\n");
                //showPacket(m);

                //Change IP Address
                iph->saddr = htonl (0xC87F7610);

                //Recalculate checksum
                iph->check = 0;
                iph->check = checksum ((unsigned short *) iph, iph->ihl * 4);

                //Accept packet
                //status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
                status =
                    ipq_set_verdict (h, m->packet_id, NF_ACCEPT, m->data_len,
                                     m->payload);

                if (status < 0)
                    die (h);
                break;
            }

        default:
            fprintf (stderr, "Unknown message type!\n");
            break;
        }
    } while (1);

    ipq_destroy_handle (h);
    return 0;
}
