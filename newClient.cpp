#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //for exit(0);
#include<sys/socket.h>
#include<errno.h> //For errno - the error number
#include<netdb.h> //hostend
#include<arpa/inet.h>
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<unistd.h>
#include<time.h>

#include<thread>

// Blatantly copied from: https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct pseudo_header    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
     
    struct tcphdr tcp;
};

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

// Modified from: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
uint32_t get_local_address()
{

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
 
    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;
 
    struct sockaddr_in serv;
 
    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );
 
    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
 
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    close(sock);

    return name.sin_addr.s_addr;
}

// From: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct iphdr* get_ip_header(char *datagram, uint32_t source_address, uint32_t destination_address) {
    struct iphdr *iph = (struct iphdr *) datagram;

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons (3525);
    iph->frag_off = htons(16384);
    iph->ttl = 20;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = source_address;
    iph->daddr = destination_address;
     
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    return iph;
}

// flag logic from: https://github.com/chinmay29/PortScanner/blob/master/PortScanner.cpp
// Structure from:  https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
struct tcphdr* get_tcp_header(char *datagram, uint8_t flags) {
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));

    //TCP Header
    tcph->source = 0; // Set later
    tcph->dest = 0; // Set later
    tcph->seq = htonl(3434);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = TH_FIN & flags ? 1 : 0;
    tcph->syn = TH_SYN & flags ? 1 : 0;
    tcph->rst = TH_RST & flags ? 1 : 0;
    tcph->psh = TH_PUSH & flags ? 1 : 0; // Why are you like this!?
    tcph->ack = TH_ACK & flags ? 1 : 0;
    tcph->urg = TH_URG & flags ? 1 : 0;
    tcph->window = htons ( 14600 );
    tcph->check = 0;
    tcph->urg_ptr = 0;

    return tcph;
}

void disable_os_header(int s) {
    int one = 1;
    const int *val = &one;
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
        exit(0);
    }
}

void analyze_response(char *datagram, uint32_t server_address) {
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(iphdr));

    uint32_t received_address = iph->saddr;
    if((tcph->syn == 1) && (tcph->ack == 1) && (server_address == received_address)) {
        printf("%d is open\n", ntohs(tcph->source));
    }
    else if(server_address == received_address) {
        // printf("%d is closed\n", ntohs(tcph->dest));
    }
}

#include <iostream>
void sniff(uint32_t server_address) {
    int response_size;

    char datagram[4096];
    memset(&datagram, 0, 4096);

    // struct sockaddr server;
    // socklen_t server_size = sizeof(server);
    // memset(&server, 0, server_size);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    // select timeout from: https://programmersheaven.com/discussion/353252/how-to-set-timeout-for-recvfrom-method
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(s, &socks);
    struct timeval t;
    t.tv_sec = 3;

    while(true) {
        if(select(s+1, &socks, NULL, NULL, &t)) {
            response_size = recvfrom(s, datagram, sizeof(datagram), 0, NULL, NULL);

            if(response_size > 0) {
                analyze_response(datagram, server_address);
            }
        }
        else {
            return;
        }
    }
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
       fprintf(stderr,"usage %s hostname\n", argv[0]);
       exit(0);
    }

    struct sockaddr_in source_in, destination_in;
    struct hostent *destination;
    struct pseudo_header psh;

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Datagram to represent the packet
    char datagram[4096];
    memset (&datagram, 0, 4096); /* zero out the buffer */

    // Get destination hostent
    destination = gethostbyname(argv[1]);
    bcopy((char *)destination->h_addr,
        (char *)&destination_in.sin_addr.s_addr,
        destination->h_length);

    // Get source address
    uint32_t source_address = get_local_address();
    uint32_t destination_address = destination_in.sin_addr.s_addr;

    if (destination == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    destination_in.sin_family = AF_INET;

    //IP header
    struct iphdr *iph = get_ip_header(datagram, source_address, destination_address);
    
    //TCP header
    struct tcphdr *tcph = get_tcp_header(datagram, TH_SYN);

    disable_os_header(s);

    std::thread sniffer_thread(sniff, destination_address);

    srand(time(NULL));  // Seed random function

    for(int portno = 0; portno < 10000; ++portno) {        
        tcph->source = htons((rand() % 2000) + 2000); // Get a random port in range 1999 - 3999
        tcph->dest = htons(portno);
        tcph->check = 0;
            
        psh.source_address = source_address;
        psh.dest_address = destination_address;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr) );
            
        memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));


        if ( sendto (s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &destination_in, sizeof (destination_in)) < 0)
        {
            printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
            exit(0);
        }
    }

    sniffer_thread.join();

    return 0;
}
