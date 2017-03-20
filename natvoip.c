/*
* This code is GPL.
*/
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libipq/libipq.h>

#define BUFSIZE 2048 
char IPNew[20]= "";
int IPNewLen = 0;
int Debug = 1;

/* Destroy handle
*/
static void die(struct ipq_handle *h)
{
        ipq_perror("passer");
        ipq_destroy_handle(h);
	exit(1);
}

/* Show Packet to screen
*/
void showPacket(ipq_packet_msg_t *pkt){
	int i=0;
	printf("\n Raw packet: --------------------------\n");
	for(i=0;i<pkt->data_len;i++){
		printf("%c", pkt->payload[i]);
	}
	printf("\n End of raw packet ------------------\n");
}

/* Get the position of the first byte of the first apearence of Flag
*/
int GetFlagPos(char * Buffer, int BufferLen, int InitialPos, char * Flag, int FlagLen ){
	int i;
	for (i=InitialPos; i<BufferLen; i++){
		if (!memcmp(Buffer + i , Flag, FlagLen)){
			return i;
		}		
	}
	return 0;
}

/* Get the position of the last byte of the first apearence of Flag
*/
int GetFlagPosEnd(char * Buffer, int BufferLen, int InitialPos, char * Flag, int FlagLen){
	int i;
	for (i=InitialPos; i<BufferLen; i++){
		if (!memcmp(Buffer + i , Flag, FlagLen)){
			return i + FlagLen;
		}		
	}
	return 0;
}

/* reverse:  reverse string s in place
*/
void reverse(char s[], int length)
{
	int i, j;
	char temp[length];

	for (i = 0, j = length-1; i<length; i++, j--) {
		temp[j] = s[i];
	}
	strcpy(s, temp);
	s[length] = '\0';
}

/* itoa:  convert n to characters in s
*/
void itoa(int n, char s[])
{
	int i, sign;

	if ((sign = n) < 0)  /* record sign */
		n = -n;          /* make n positive */
	i = 0;
	do {       /* generate digits in reverse order */
		s[i++] = n % 10 + '0';   /* get next digit */
	} while ((n /= 10) > 0);     /* delete it */
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s, strlen(s));
}

/* Change Packet replacing Txt
*/

void ChangePacket(ipq_packet_msg_t * m, int TxtOrigPos, int TxtOrigLen, char TxtNew[], int TxtNewLen){
	int OrigDataLen;
	unsigned char PayloadOrig [BUFSIZE];
		
	//Backup data
	memcpy(PayloadOrig, m->payload, m->data_len);
	OrigDataLen = m->data_len;
	
	//Change Txt
	memcpy(m->payload + TxtOrigPos, TxtNew, TxtNewLen);
	memcpy(m->payload + TxtOrigPos + TxtNewLen, PayloadOrig + TxtOrigPos + TxtOrigLen, OrigDataLen - TxtOrigPos - TxtOrigLen);
	m->data_len = OrigDataLen - TxtOrigLen + TxtNewLen;
	
}

/* Checksum for IP header 
*/
unsigned short checksum(unsigned short *addr, int len)
{
	int nleft=len;
	int sum=0;
	unsigned short *w=addr;
	unsigned short answer=0;

	while(nleft>1){
		sum+=*w++;
		nleft-=2;
	}
	if(nleft==1){
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;     
	}
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
}

/* Check packet to find an IP address to change
*/
int checkPacket(ipq_packet_msg_t * m){
	int i = 0;
	int TxtOrigPos = 0;
	int TxtOrigLen = 0;
	unsigned char TxtOrig [20] = "";
	int TxtNewLen = 0;
	unsigned char TxtNew [20] = "";
	int IPOrigLen = 0;
	unsigned char IPOrig [20] = "";
	int Pos1, Pos2, Pos3;
	int TxtChange = 0;
	int SDPChange = 0;
	int PacketSizeChange = 0;
	int SDPSizeChange = 0;
	
	//Cast to IP
	struct iphdr *iph = ((struct iphdr *) m->payload);
			
	//If not UDP exit
	if (iph->protocol != 17) return 1;
	
	//Cast to UDP
	struct udphdr *udp = (struct udphdr *) (m->payload + (iph->ihl << 2));
		
	if (Debug) fprintf(stderr, "**********Packet**********\n");
	
	//Search for Contact
	
	Pos1 = GetFlagPosEnd(m->payload, m->data_len, 0, "Contact: <sip:", 14);
	if (Pos1){
		TxtChange = 1;
		if (Debug) fprintf(stderr, "***Contact\n");
		Pos1 = GetFlagPos(m->payload, m->data_len, Pos1, "@", 1);
		TxtOrigPos = Pos1 + 1;
		Pos2 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, ":", 1);
		Pos3 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, ";", 1);
		if (Pos3 && Pos3 < Pos2) Pos2 = Pos3;
		TxtOrigLen = Pos2 - TxtOrigPos;
		if (Debug) fprintf(stderr, "Contact Len: %d\n", TxtOrigLen);
		memcpy (TxtOrig, m->payload + TxtOrigPos, TxtOrigLen);
		TxtOrig[TxtOrigLen] = 0;
		if (Debug) fprintf(stderr, "Contact: %s\n", TxtOrig);

		IPOrigLen = TxtOrigLen;
		memcpy (IPOrig, TxtOrig, TxtOrigLen);

		ChangePacket(m, TxtOrigPos, TxtOrigLen, IPNew, IPNewLen);

		PacketSizeChange = PacketSizeChange - TxtOrigLen + IPNewLen;
	}

	//Search for SDP

	Pos1 = GetFlagPosEnd(m->payload, m->data_len, 0, " IN IP4 ", 8);
	if (Pos1){
		TxtChange = 1;
		SDPChange++;
		if (Debug) fprintf(stderr, "***SDP1\n");
		TxtOrigPos = Pos1;
		Pos2 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\n", 1);
		Pos3 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\r", 1);
		if (Pos3 && Pos3 < Pos2) Pos2 = Pos3;
		TxtOrigLen = Pos2 - TxtOrigPos;
		if (Debug) fprintf(stderr, "SDP1 Len: %d\n", TxtOrigLen);
		memcpy (TxtOrig, m->payload + TxtOrigPos, TxtOrigLen);
		TxtOrig[TxtOrigLen] = 0;
		if (Debug) fprintf(stderr, "SDP1: %s\n", TxtOrig);
	
		IPOrigLen = TxtOrigLen;
		memcpy (IPOrig, TxtOrig, TxtOrigLen);

		ChangePacket(m, TxtOrigPos, TxtOrigLen, IPNew, IPNewLen);
		
		SDPSizeChange = SDPSizeChange - TxtOrigLen + IPNewLen;
		PacketSizeChange = PacketSizeChange - TxtOrigLen + IPNewLen;
		
	}
	
	//Search for SDP
	
	Pos1 = GetFlagPosEnd(m->payload, m->data_len, 0, "c=IN IP4 ", 9);
	if (Pos1){
		TxtChange = 1;
		SDPChange++;
		if (Debug) fprintf(stderr, "***SDP2\n");
		TxtOrigPos = Pos1;
		Pos2 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\n", 1);
		Pos3 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\r", 1);
		if (Pos3 && Pos3 < Pos2) Pos2 = Pos3;
		TxtOrigLen = Pos2 - TxtOrigPos;
		if (Debug) fprintf(stderr, "SDP2 Len: %d\n", TxtOrigLen);
		memcpy (TxtOrig, m->payload + TxtOrigPos, TxtOrigLen);
		TxtOrig[TxtOrigLen] = 0;
		if (Debug) fprintf(stderr, "SDP2: %s\n", TxtOrig);

		IPOrigLen = TxtOrigLen;
		memcpy (IPOrig, TxtOrig, TxtOrigLen);

		ChangePacket(m, TxtOrigPos, TxtOrigLen, IPNew, IPNewLen);
		
		SDPSizeChange = SDPSizeChange - TxtOrigLen + IPNewLen;
		PacketSizeChange = PacketSizeChange - TxtOrigLen + IPNewLen;
		
	}
	
	//Search for Content-Length
	
	if (SDPChange){
		Pos1 = GetFlagPosEnd(m->payload, m->data_len, 0, "Content-Length: ", 16);
		if (Pos1){
			TxtChange = 1;
			if (Debug) fprintf(stderr, "***Content-Length\n");
			TxtOrigPos = Pos1;
			Pos2 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\n", 1);
			Pos3 = GetFlagPos(m->payload, m->data_len, TxtOrigPos, "\r", 1);
			if (Pos3 && Pos3 < Pos2) Pos2 = Pos3;
			TxtOrigLen = Pos2 - TxtOrigPos;
			if (Debug) fprintf(stderr, "Content-Length Len: %d\n", TxtOrigLen);
			memcpy (TxtOrig, m->payload + TxtOrigPos, TxtOrigLen);
			TxtOrig[TxtOrigLen] = 0;
			if (Debug) fprintf(stderr, "Content-Length: %s\n", TxtOrig);
			itoa(atoi(TxtOrig) + SDPSizeChange, TxtNew);
			TxtNewLen = strlen(TxtNew);
			if (Debug) fprintf(stderr, "Content-Length New Len: %d\n", TxtNewLen);
			if (Debug) fprintf(stderr, "Content-Length New : %s\n", TxtNew);
	
			ChangePacket(m, TxtOrigPos, TxtOrigLen, TxtNew, TxtNewLen);
		
			PacketSizeChange = PacketSizeChange - TxtOrigLen + TxtNewLen;
			
		}
	}
	
	if (TxtChange){
		//Change Length
		iph->tot_len = htons(ntohs(iph->tot_len) + PacketSizeChange);
		udp->len = htons(ntohs(udp->len) + PacketSizeChange);
		//Recalculate checksum
		udp->check=0;
		iph->check=0;
		iph->check=checksum((unsigned short*)iph,iph->ihl*4);
	}

}				

int main(int argc, char **argv)
{
        int status;
        unsigned char buf[BUFSIZE];
        struct ipq_handle *h;
	unsigned int iphl;
	int i;

	printf("natVoip is starting\n");

	/*Check arguments

	if (Debug){
		printf("Number of aguments: %d \n", argc);
		for (i=0; i<argc; i++ ) printf("Argument[%d] = %s \n", i, *(argv+i));
	}
	*/
		
	switch (argc){
		case 5:
			if (!strcmp(*(argv+1), "-ip")){
				strcpy(IPNew, *(argv+2));
				IPNewLen = strlen(IPNew);
				printf("natVoip is using IP Address: %s\n", IPNew);
			}
			else {
				printf("Usage: natVoip -ip [IP Address] -d [Debug]\n");
				exit (1);
			}
			if (!strcmp(*(argv+3), "-d")){
				Debug = atoi(*(argv+4));
				printf("natVoip is with Debug: %d\n", Debug);
			}
			else {
				printf("Usage: natVoip -ip [IP Address] -d [Debug]\n");
				exit (1);
			}
			break;
		default:
			printf("Usage: natVoip -ip [IP Address] -d [Debug]\n");
			exit(1);
			break;
	}

	/*Use for default config
	 
		strcpy(IPNew, "200.127.118.16");
		IPNewLen = 14;
	*/
	
	/*Use for read ConfigFile
	
		ConfigFile = fopen("/root/iptables/natVoip.cfg", "r");
	
		if (ConfigFile){
			fgets(IPNew, 1024, ConfigFile);
			if(IPNew[strlen(IPNew)-1] == 0x0a) IPNew[strlen(IPNew)-1] = 0;
			IPNewLen = strlen(IPNew);
		}else
			exit(1);

	*/

	//if (Debug) fprintf(stderr, "IPNew: %s IPLen: %d\n", IPNew, IPNewLen);
		
        h = ipq_create_handle(0, PF_INET);
        if (!h)
                die(h);
                
        status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
        if (status < 0)
                die(h);
                
        do{
                status = ipq_read(h, buf, BUFSIZE, 0);
                if (status < 0)
                        die(h);
                        
                switch (ipq_message_type(buf)) {
                        case NLMSG_ERROR:
                                fprintf(stderr, "Received error message %d\n", ipq_get_msgerr(buf));
                                break;
                                
                        case IPQM_PACKET: {
                                ipq_packet_msg_t *m = ipq_get_packet(buf);
			
				checkPacket(m);
					
				//Accept packet
				//status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, 0, NULL);
				status = ipq_set_verdict(h, m->packet_id, NF_ACCEPT, m->data_len, m->payload);

                                if (status < 0)
                                        die(h);
                                break;
                        }
                        
                        default:
                                fprintf(stderr, "Unknown message type!\n");
                                break;
                }
        } while (1);
        
        ipq_destroy_handle(h);
        return 0;
}
