// https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<pthread.h>
#include<netdb.h> //hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header

struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};


unsigned short csum(unsigned short *buf,int nwords)
{
	//this function returns the checksum of a buffer
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--){sum += *buf++;}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) (~sum);
}

int main(int argc, char* argv[]) {

    
    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int d = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Datagram to represent the packet
    char datagram[4096];    
     
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;
     
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));

    struct sockaddr_in source_in, destination_in;
    struct pseudo_header psh;
    struct hostent *source;
    struct hostent *destination;

    // https://stackoverflow.com/questions/22149452/creating-ethernet-frame-in-sock-raw-communication
    source = gethostbyname("192.168.1.77");
    destination = gethostbyname(argv[1]);

    if (destination == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    // source_in.sin_family = AF_INET;
    destination_in.sin_family = AF_INET;

    // source_in.sin_port = htons(3123);
    destination_in.sin_port = htons(atoi(argv[2]));

    // bcopy((char *)source->h_addr, 
    //     (char *)&source_in.sin_addr.s_addr,
    //     source->h_length);

    bcopy((char *)destination->h_addr,
        (char *)&destination_in.sin_addr.s_addr,
        destination->h_length);

    // printf("Source address: %d\n", source->h_addr);
    printf("Destination address: %d\n", destination->h_addr);

    // printf("Local source IP is %s \n" , source_in.sin_port);

    memset (&datagram, 0, 4096); /* zero out the buffer */

    //Fill in the IP Header
    iph->ihl = 5; // TRY CHANGING TO 4
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (3525); //Id of this packet
    iph->frag_off = htons(16384);
    iph->ttl = 20;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Set to 0 before calculating checksum
    iph->saddr = inet_addr("192.168.1.77"); // source_in.sin_addr.s_addr;
    iph->daddr = destination_in.sin_addr.s_addr;
     
    iph->check = 0;
     
    //TCP Header
    tcph->source = htons(3123);
    tcph->dest = destination_in.sin_port;
    tcph->seq = htonl(3434);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;      //Size of tcp header
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons ( 14600 );  // maximum allowed window size
    tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
    tcph->urg_ptr = 0;

    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }

    // tcph->dest = htons ( port );

    psh.source_address = iph->saddr; //source_in.sin_addr.s_addr;
    psh.dest_address = destination_in.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons( sizeof(struct tcphdr) );
        
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = 0x5248; //csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
        
    //Send the packet
    printf("Sending the thing\n");
    if ( sendto (s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &destination_in, sizeof (destination_in)) < 0)
    {
        printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    printf("Sent it\n");

    return 0;
}