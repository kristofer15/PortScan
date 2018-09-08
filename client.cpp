#include <stdio.h> //printf
#include <string.h> //memset
#include <stdlib.h> //for exit(0);
#include <sys/socket.h>
#include <errno.h> //For errno - the error number
#include <netdb.h> //hostend
#include <arpa/inet.h>
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <unistd.h>
#include <time.h>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <algorithm>    // std::random_shuffle
#include <iostream>

#include "file_reader.h"

// TODO: CHANGE ME PROBABLY
std::mutex PORT_MUTEX;

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

// TODO: templates
void exclusive_push(std::list<int> &l, int value) {
    std::lock_guard<std::mutex> guard(PORT_MUTEX);
    l.push_back(value);
}

void exclusive_remove(std::list<int> &l, int value) {
    std::lock_guard<std::mutex> guard(PORT_MUTEX);
    l.remove(value);
}

void exclusive_print(std::list<int> l) {
    std::list<int>::iterator it;
    
    for(it = l.begin(); it != l.end(); ++it) {
        std::cout << *it << std::endl;
    }
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

void analyze_response(char *datagram, uint32_t server_address, std::list<int> &hit_ports, uint8_t desired_flags) {
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(iphdr));

    uint32_t received_address = iph->saddr;
    uint8_t received_flags = 0;

    // Collect received flags
    received_flags |= tcph->ack ? TH_ACK : 0;
    received_flags |= tcph->syn ? TH_SYN : 0;
    received_flags |= tcph->fin ? TH_FIN : 0;
    received_flags |= tcph->rst ? TH_RST : 0;

    if(server_address == received_address) {

        if(ntohs(tcph->source == 631))  {
            std::cout << "Received 631" << std::endl;
        }

        exclusive_remove(hit_ports, ntohs(tcph->source));

        // received_flags are desired_flags and the address is correct
        if((received_flags == desired_flags) && (server_address == received_address)) {
            printf("%d is open\n", ntohs(tcph->source));
        }
        else if(server_address == received_address) {
            // printf("%d is closed\n", ntohs(tcph->dest));
        }
    }
}

void sniff(uint32_t server_address, std::list<int> &hit_ports, uint8_t desired_flags) {
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
                analyze_response(datagram, server_address, hit_ports, desired_flags);
            }
        }
        else {
            std::cout << "No response received from:" << std::endl;
            exclusive_print(hit_ports);
            return;
        }
    }
}

void hit_tcp(const char *host_name, std::vector<int> &ports, uint8_t out_flags, uint8_t in_flags) {
    struct sockaddr_in source_in, destination_in;
    struct hostent *destination;
    struct pseudo_header psh;
    std::mutex hit_port_mutex;
    std::list<int> hit_ports;

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    //Datagram to represent the packet
    char datagram[4096];
    memset (&datagram, 0, 4096); /* zero out the buffer */

    // Get destination hostent
    destination = gethostbyname(host_name);
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
    struct tcphdr *tcph = get_tcp_header(datagram, out_flags);

    disable_os_header(s);

    std::thread sniffer_thread(sniff, destination_address, std::ref(hit_ports), in_flags);

    srand(time(NULL));  // Seed random function

    for(int destination_port : ports) {        
        tcph->source = htons((rand() % 2000) + 2000); // Get a random port in range 2000 - 3999
        tcph->dest = htons(destination_port);
        tcph->check = 0;
            
        psh.source_address = source_address;
        psh.dest_address = destination_address;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons( sizeof(struct tcphdr));
            
        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

        tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));


        if ( sendto (s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &destination_in, sizeof (destination_in)) < 0)
        {
            printf ("Error sending packet. Error number: %d . Error message: %s \n" , errno , strerror(errno));
            exit(0);
        }

        if(destination_port == 631) {
            std::cout << "Added 631" << std::endl;
        }

        exclusive_push(hit_ports, destination_port);
    }

    sniffer_thread.join();
}

void scan_host(int option, const char *host_name, std::vector<int> &ports) {

    switch(option) {
        case 's':   // SYN scan
            hit_tcp(host_name, ports, TH_SYN, TH_SYN|TH_ACK);
            return;
        case 'n':   // NULL scan
            hit_tcp(host_name, ports, 0, 0);
            // out = 0;
            // in = 0;
            return;
        case 'x':   // XMAS scan
            // out = 0b11111111;
            // in = 0;
            return;
        case 'f':   // FIN scan
            // out = TH_FIN;
            // in = 0;
            return;
        default:
            error("Scan option not recognized");
    }
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
       fprintf(stderr,"usage %s hostname\n", argv[0]);
       exit(0);
    }

    int c = -1;
    int option = -1;
    
    while((c = getopt(argc, argv, "snxf")) != -1) {

        if(option != -1) {
            error("Too many scan options. Please specify one of [snxf]\n");
        }
        
        option = c;
    }

    if(option == -1) {
        error("Scan option missing. Please specify one of [snxf]\n");
    }

    std::vector<int> ports = get_lines("ports.txt");
    std::vector<std::string> hosts = {"localhost"};

    // set seed for random_shuffle()
    std::srand(unsigned(std::time(0)));

    // Shuffle targets
    std::random_shuffle(ports.begin(), ports.end());
    std::random_shuffle(hosts.begin(), hosts.end());

    // TODO: Multithread me
    for(const std::string host : hosts) {
        scan_host(option, host.c_str(), ports);
    }

    return 0;
}
